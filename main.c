#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

typedef struct MappedFile
{
    struct MappedFile *next;

    int major;
    int minor;
    int inode;
    char *filename;

    // Read/write/execute perms on the mapped file.
    // Inferred from the various mappings.
    int perms;

    // The length in bytes of the two bitmaps
    // below.
    int bitmap_length;

    // Bitmap of all page-sized blocks within
    // the file that are mapped.
    unsigned char *mapped_pages;

    // Bitmap of all page-sized blocks that
    // have been mapped more than once.
    unsigned char *shared_pages;
} MappedFile;

typedef struct Mapping
{
    struct Mapping *next;

    char *start_address;
    size_t length;

    int perms;
    int flags;

    int major;
    int minor;
    int inode;
    size_t offset;

    char *filename;
} Mapping;

typedef struct Process
{
    struct Process *next;

    pid_t pid;
    Mapping *mappings;

    // Stats
    size_t unique_text;
    size_t shared_text;
    size_t unique_data;
    size_t shared_data;

    size_t total_mapped_memory;
} Process;

typedef struct SummaryStats
{
    size_t total_unique_text;
    size_t total_shared_text;
    size_t total_unique_data;
    size_t total_shared_data;

    size_t total_mapped_memory;
} SummaryStats;

static int max(int a, int b) {
    return a > b ? a : b;
}

static bool is_pid_dir(const char *filename)
{
    while (*filename) {
        if (!isdigit(*filename))
            return false;
        filename++;
    }
    return true;
}

static Mapping *load_mappings(const char *mapfile)
{
    Mapping *mappings = 0;
    FILE *fp = fopen(mapfile, "r");
    if (fp == NULL)
        return mappings;

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        Mapping *mapping = (Mapping *) malloc(sizeof(Mapping));

        // Start address
        char *str = strtok(line, "-");
        if (str == NULL) {
            printf("Unexpected string: %s\n", line);
            free(mapping);
            break;
        }
        mapping->start_address = (char *) strtoull(str, 0, 16);

        // End address
        str = strtok(NULL, " \t");
        char *end_address = (char *) strtoull(str, 0, 16);
        mapping->length = end_address - mapping->start_address;

        // Permissions
        str = strtok(NULL, " \t");
        mapping->perms = (str[0] == 'r' ? PROT_READ : 0) |
                (str[1] == 'w' ? PROT_WRITE : 0) |
                (str[2] == 'x' ? PROT_EXEC : 0);
        mapping->flags = (str[3] == 'p' ? MAP_PRIVATE : MAP_SHARED);

        // Offset
        str = strtok(NULL, " \t");
        mapping->offset = strtoul(str, 0, 16);

        // Major
        str = strtok(NULL, ":");
        mapping->major = strtol(str, 0, 16);

        // Minor
        str = strtok(NULL, " \t");
        mapping->minor = strtol(str, 0, 16);

        // Inode
        str = strtok(NULL, " \t");
        mapping->inode = strtol(str, 0, 10);

        // Filename (optional)
        str = strtok(NULL, " \t\n");
        if (str != NULL)
            mapping->filename = strdup(str);
        else
            mapping->filename = 0;

        mapping->next = mappings;
        mappings = mapping;
    }
    fclose(fp);
    return mappings;
}

static Process *load_all_mappings()
{
    Process *processes = 0;

    DIR *d = opendir("/proc");
    struct dirent *entry = NULL;

    while ((entry = readdir(d))) {
        if (is_pid_dir(entry->d_name)) {
            Process *process = (Process *) malloc(sizeof(Process));
            process->pid = strtol(entry->d_name, 0, 10);

            char mapfile[PATH_MAX];
            sprintf(mapfile, "/proc/%d/maps", process->pid);
            process->mappings = load_mappings(mapfile);


            process->next = processes;
            processes = process;
        }
    }

    closedir(d);
    return processes;
}

static MappedFile *find_mapped_file(MappedFile *mappedFiles, int major, int minor, int inode)
{
    MappedFile *mappedFile;
    for (mappedFile = mappedFiles; mappedFile != NULL; mappedFile = mappedFile->next) {
        if (mappedFile->major == major &&
                mappedFile->minor == minor &&
                mappedFile->inode == inode)
            return mappedFile;
    }
    return 0;
}

static void add_or_update_mapped_file(MappedFile **mappedFiles, Mapping *mapping)
{
    // Check if this mapping doesn't go to a file
    if (mapping->major == 0)
        return;

    int lastBitOffset = ((mapping->offset + mapping->length) / 4096 / 8) + 1;

    MappedFile *mappedFile = find_mapped_file(*mappedFiles, mapping->major, mapping->minor, mapping->inode);
    if (!mappedFile) {
        mappedFile = (MappedFile*) malloc(sizeof(MappedFile));
        memset(mappedFile, 0, sizeof(MappedFile));

        mappedFile->major = mapping->major;
        mappedFile->minor = mapping->minor;
        mappedFile->inode = mapping->inode;
        mappedFile->filename = strdup(mapping->filename);

        mappedFile->next = *mappedFiles;
        *mappedFiles = mappedFile;

        mappedFile->bitmap_length = max(1024, lastBitOffset);
        mappedFile->mapped_pages = malloc(mappedFile->bitmap_length);
        mappedFile->shared_pages = malloc(mappedFile->bitmap_length);
        memset(mappedFile->mapped_pages, 0, mappedFile->bitmap_length);
        memset(mappedFile->shared_pages, 0, mappedFile->bitmap_length);
    }

    // Expand the bitmap if necessary.
    if (mappedFile->bitmap_length < lastBitOffset) {
        mappedFile->mapped_pages = realloc(mappedFile->mapped_pages, lastBitOffset);
        mappedFile->shared_pages = realloc(mappedFile->shared_pages, lastBitOffset);
        memset(&mappedFile->mapped_pages[mappedFile->bitmap_length], 0, lastBitOffset - mappedFile->bitmap_length);
        memset(&mappedFile->shared_pages[mappedFile->bitmap_length], 0, lastBitOffset - mappedFile->bitmap_length);
        mappedFile->bitmap_length = lastBitOffset;
    }

    // Update permissions
    mappedFile->perms |= mapping->perms;

    // Fill out the bitmap.
    size_t lastOffset = mapping->offset + mapping->length;
    size_t offset;
    for (offset = mapping->offset; offset < lastOffset; offset += 4096) {
        int bitOffset = offset / 4096 / 8;
        int bitMask = 1 << ((offset / 4096) % 8);

        if (mappedFile->mapped_pages[bitOffset] & bitMask)
            mappedFile->shared_pages[bitOffset] |= bitMask;
        else
            mappedFile->mapped_pages[bitOffset] |= bitMask;
    }
}

static MappedFile *build_mapped_file_list(Process *processes)
{
    MappedFile *mappedFiles = 0;
    Process *process;
    for (process = processes; process != NULL; process = process->next) {
        Mapping *mapping;
        for (mapping = process->mappings; mapping != NULL; mapping = mapping->next) {
            add_or_update_mapped_file(&mappedFiles, mapping);
        }
    }
    return mappedFiles;
}

static void calculate_overlaps(Mapping *mapping, MappedFile *mappedFile, size_t *uniqueLength, size_t *sharedLength)
{
    *sharedLength = 0;
    *uniqueLength = 0;

    size_t lastOffset = mapping->offset + mapping->length;
    size_t offset;
    for (offset = mapping->offset; offset < lastOffset; offset += 4096) {
        int bitOffset = offset / 4096 / 8;
        int bitMask = 1 << ((offset / 4096) % 8);

        if (mappedFile->shared_pages[bitOffset] & bitMask)
            *sharedLength += 4096;
        else
            *uniqueLength += 4096;
    }
}

static void lookup_mapping(Mapping *mapping, MappedFile *mappedFiles, size_t *uniqueLength, size_t *sharedLength)
{
    MappedFile *mappedFile;
    for (mappedFile = mappedFiles; mappedFile != NULL; mappedFile = mappedFile->next) {
        if (mappedFile->inode == mapping->inode &&
                mappedFile->major == mapping->major &&
                mappedFile->minor == mapping->minor) {
            calculate_overlaps(mapping, mappedFile, uniqueLength, sharedLength);
            break;
        }
    }
}

static void compute_process_stats(Process *process, MappedFile *mappedFiles)
{
    process->unique_text = 0;
    process->shared_text = 0;
    process->unique_data = 0;
    process->shared_data = 0;

    Mapping *mapping;
    for (mapping = process->mappings; mapping != NULL; mapping = mapping->next) {
        // Skip fence-post mappings that won't use physical memory
        if (mapping->perms == 0)
            continue;

        size_t uniqueLength;
        size_t sharedLength;
        if (mapping->major == 0) {
            // If not mapped to a device, then this memory is only mapped
            // to this process. ** Check assumption **
            uniqueLength = mapping->length;
            sharedLength = 0;
        } else {
            lookup_mapping(mapping, mappedFiles, &uniqueLength, &sharedLength);
        }

        // Logic: if it's writable, then it's data, else text.
        if (mapping->perms & PROT_WRITE) {
            // Data
            process->unique_data += uniqueLength;
            process->shared_data += sharedLength;
        } else {
            // Text
            process->unique_text += uniqueLength;
            process->shared_text += sharedLength;
        }
    }

    process->total_mapped_memory =
            process->unique_data +
            process->unique_text +
            process->shared_data +
            process->shared_text;
}

static int count_bits(unsigned char c)
{
    int count = 0;
    int i;
    for (i = 0; i < 8; i++)
        if (c & (1 << i))
            count++;
    return count;
}

static void compute_shared_mappings(MappedFile *mappedFile,
                                    size_t *shared_text,
                                    size_t *shared_data)
{
    // Count the number of bits.
    int total_bits = 0;
    int i;
    for (i = 0; i < mappedFile->bitmap_length; i++)
        total_bits += count_bits(mappedFile->shared_pages[i]);

    if (mappedFile->perms & PROT_WRITE)
        *shared_data = total_bits * 4096;
    else
        *shared_text = total_bits * 4096;
}

static void compute_unique_mappings(MappedFile *mappedFile,
                                    size_t *unique_text,
                                    size_t *unique_data)
{
    // Count the number of bits.
    int total_bits = 0;
    int i;
    for (i = 0; i < mappedFile->bitmap_length; i++)
        total_bits += count_bits(mappedFile->mapped_pages[i] & ~mappedFile->shared_pages[i]);

    if (mappedFile->perms & PROT_WRITE)
        *unique_data = total_bits * 4096;
    else
        *unique_text = total_bits * 4096;
}

static void compute_all_process_stats(Process *processes,
                                      MappedFile *mappedFiles,
                                      SummaryStats *stats)
{
    memset(stats, 0, sizeof(stats));

    // Compute stats for each process
    Process *process;
    for (process = processes; process != NULL; process = process->next) {
        compute_process_stats(process, mappedFiles);

        stats->total_unique_data += process->unique_data;
        stats->total_unique_text += process->unique_text;
    }

    // Count the amount of memory that was shared between processes.
    MappedFile *mappedFile;
    for (mappedFile = mappedFiles; mappedFile != NULL; mappedFile = mappedFile->next) {
        size_t shared_data;
        size_t shared_text;

        compute_shared_mappings(mappedFile, &shared_text, &shared_data);
        stats->total_shared_data += shared_data;
        stats->total_shared_text += shared_text;
    }

    stats->total_mapped_memory =
            stats->total_unique_text +
            stats->total_shared_text +
            stats->total_unique_data +
            stats->total_shared_data;
}

static int process_count(Process *processes)
{
    int i = 0;
    while (processes) {
        processes = processes->next;
        i++;
    }
    return i;
}

static int process_compare(const void *p1, const void *p2)
{
    const Process *process1 = *(const Process **) p1;
    const Process *process2 = *(const Process **) p2;

    if (process1->total_mapped_memory < process2->total_mapped_memory)
        return 1;
    else if (process1->total_mapped_memory > process2->total_mapped_memory)
        return -1;
    else
        return 0;
}

static Process *sort_processes(Process *processes)
{
    int count = process_count(processes);

    Process **process_array = (Process **) alloca(count * sizeof(Process*));
    Process *process = processes;
    int i;
    for (i = 0; i < count; i++) {
        process_array[i] = process;
        process = process->next;
    }

    qsort(process_array, count, sizeof(Process*), process_compare);

    for (i = 0; i < count - 1; i++)
        process_array[i]->next = process_array[i + 1];
    process_array[count - 1]->next = 0;

    return process_array[0];
}

static char *pid_to_name(pid_t pid)
{
    char *filename;
    asprintf(&filename, "/proc/%d/cmdline", pid);
    FILE *fp = fopen(filename, "r");
    free(filename);

    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp);
        fclose(fp);

        return strdup(line);
    } else
        return strdup("");
}

static const char *strright(const char *str, int n)
{
    return str + max(0, strlen(str) - n);
}

static void print_stats(Process *processes, MappedFile *mappedFiles, SummaryStats *stats)
{
    printf("Processes sorted by total amount of mapped memory:\n\n");

    printf("                Name    PID  Unique text  Shared text  Unique data  Shared data        Total\n");
    Process *process;
    for (process = processes; process != NULL; process = process->next) {
        // Don't print processes that don't have any mappings.
        if (process->total_mapped_memory == 0)
            continue;

        char *name = pid_to_name(process->pid);
        printf("%20.20s %6d %12zu %12zu %12zu %12zu %12zu\n",
               strright(name, 20),
               process->pid,
               process->unique_text,
               process->shared_text,
               process->unique_data,
               process->shared_data,
               process->total_mapped_memory);
        free(name);
    }

    printf("\nMapped files sorted by size mapped:\n\n");
    printf("                Name     Unique text  Shared text  Unique data  Shared data        Total\n");
    MappedFile *mappedFile;
    for (mappedFile = mappedFiles; mappedFile != NULL; mappedFile = mappedFile->next) {
        size_t shared_text;
        size_t shared_data;
        size_t unique_text;
        size_t unique_data;
        compute_unique_mappings(mappedFile, &unique_text, &unique_data);
        compute_shared_mappings(mappedFile, &shared_text, &shared_data);
        printf("%20.20s %12zu %12zu %12zu %12zu %12zu\n",
               strright(mappedFile->filename, 20),
               unique_text,
               shared_text,
               unique_data,
               shared_data,
               unique_data + unique_text + shared_data + shared_text);

    }

    printf("\nSummary\n");
    printf("Total amount of unique read-only/text data: %zu bytes\n", stats->total_unique_text);
    printf("Total amount of shared read-only/text data: %zu bytes\n", stats->total_shared_text);
    printf("Total amount of private or singly mapped writable data: %zu bytes\n", stats->total_unique_data);
    printf("Total amount of shared writable data: %zu bytes\n", stats->total_shared_data);
    printf("Sum total of mapped memory: %zu bytes\n", stats->total_mapped_memory);
}

int main(int argc, char *argv[])
{
    Process *processes = load_all_mappings();

    MappedFile *mappedFiles = build_mapped_file_list(processes);

    SummaryStats stats;
    compute_all_process_stats(processes, mappedFiles, &stats);

    // Sort the processes based on amount of memory mapped.
    processes = sort_processes(processes);

    print_stats(processes, mappedFiles, &stats);

    exit(EXIT_SUCCESS);
}

