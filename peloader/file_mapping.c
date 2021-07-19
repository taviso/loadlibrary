#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "file_mapping.h"


void AddMappedFile(MappedFileEntry *mapped_file, MappedFileObjectList *list)
{
    MappedFileEntry *current;

    if (list->head == NULL) {
        list->head = mapped_file;
        return;
    }

    current = list->head;

    while(current->next != NULL) {
        current = current->next;
    }

    current->next = mapped_file;
}

bool DeleteMappedFile(MappedFileEntry *mapped_file, MappedFileObjectList *list)
{
    MappedFileEntry *to_delete = NULL;

    if (list == NULL)
        return false;

    MappedFileEntry *current = list->head;

    // mapped_file is the first in the list
    if (current == mapped_file) {
        to_delete = current;
        list->head = NULL;
        free(to_delete);
        return true;
    }

    while(current != NULL) {
        if (current->next == mapped_file) {
            to_delete = current->next;
            current->next = to_delete->next;
            free(to_delete);
            return true;
        }
        current = current->next;
    }

    return false;
}

MappedFileEntry* SearchMappedFile(MappedFileEntry *mapped_file, MappedFileObjectList *list)
{
    if (list == NULL)
        return NULL;
    MappedFileEntry *current = list->head;
    while(current != NULL && current != mapped_file)
        current = current->next;
    return current;
}
