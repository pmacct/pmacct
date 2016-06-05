/*
 * Copyright (c) 2009-2014 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#if (defined WITH_JANSSON) && (!defined HAVE_JSON_OBJECT_UPDATE_MISSING)
#include <jansson.h>

/* Introduced in Jansson 2.3. Rewritten to not use
 * json_object_foreach() macro. */
int json_object_update_missing(json_t *object, json_t *other)
{
    void *iter;

    if(!json_is_object(object) || !json_is_object(other))
        return -1;

    iter = json_object_iter(other);
    while(iter) {
        const char *key;
        json_t *value;

        key = json_object_iter_key(iter);
        if(!json_object_get(object, key)) {
            value = json_object_iter_value(iter);
            if(json_object_set_nocheck(object, key, value))
                return -1;
        }

        iter = json_object_iter_next(other, iter);
    }

    return 0;
}
#endif
