/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/projdefs.h"
#include "freertos/ringbuf.h"
#include "ssh_vfs.h"

#define MAX_CLIENTS 4
static const char* TAG = "ssh_vfs";

extern FILE *backup_in;
extern FILE *backup_out;

static ssize_t ssh_vfs_write(void* ctx, int fd, const void * data, size_t size);
static ssize_t ssh_vfs_read(void* ctx, int fd, void * dst, size_t size);
static int ssh_vfs_open(void* ctx, const char * path, int flags, int mode);
static int ssh_vfs_close(void* ctx, int fd);
static int ssh_vfs_fstat(void* ctx, int fd, struct stat * st);

typedef struct {
    ssh_channel ssh_handle;
    bool opened;
    RingbufHandle_t ssh_rb;
} ssh_vfs_desc_t;

static ssh_vfs_desc_t s_desc[MAX_CLIENTS];
static _lock_t s_lock;
static ssh_vfs_config_t s_config;

esp_err_t ssh_vfs_register(const ssh_vfs_config_t *config)
{
    s_config = *config;
    const esp_vfs_t vfs = {
        .flags = ESP_VFS_FLAG_CONTEXT_PTR,
        .open_p = ssh_vfs_open,
        .close_p = ssh_vfs_close,
        .read_p = ssh_vfs_read,
        .write_p = ssh_vfs_write,
        .fstat_p = ssh_vfs_fstat,
    };
    return esp_vfs_register(config->base_path, &vfs, NULL);
}

static ssize_t ssh_vfs_write(void* ctx, int fd, const void * data, size_t size)
{
    int sent = 0;
    const uint8_t *buf = (const uint8_t *)data;

    if (!buf || size == 0 || size > 32768) {
        return 0;
    }

    if (fd < 0 || fd > MAX_CLIENTS) {
        errno = EBADF;
        return -1;
    }

    ssh_channel channel = s_desc[fd].ssh_handle;
    if (!channel || ssh_channel_is_eof(channel)) {
        errno = EPIPE;
        return -1;
    }

    if (!ssh_channel_is_eof(channel)) {
        sent = ssh_channel_write(channel, buf, size);
        if (sent < 0) {
            errno = EIO;
            return -1;
        }
        if (buf[size-1] == '\n') {
            sent += ssh_channel_write(channel, "\r", strlen("\r"));
        }
    }

    return sent;
}

esp_err_t ssh_vfs_push_data(ssh_channel handle, const void *data, int size)
{
    int fd;
    for (fd = 0; fd < MAX_CLIENTS; ++fd) {
        if (s_desc[fd].ssh_handle == handle) {
            break;
        }
    }
    if (fd == MAX_CLIENTS) {
        return ESP_ERR_INVALID_ARG;
    }
    RingbufHandle_t rb = s_desc[fd].ssh_rb;
    if (!rb) {
        return ESP_ERR_INVALID_STATE;
    }
    BaseType_t ok = xRingbufferSend(rb, data, size, pdMS_TO_TICKS(s_config.send_timeout_ms));
    return ok == pdTRUE ? ESP_OK : ESP_ERR_TIMEOUT;
}

static ssize_t ssh_vfs_read(void* ctx, int fd, void * dst, size_t size)
{
    if (fd < 0 || fd >= MAX_CLIENTS) {
        errno = EBADF;
        return -1;
    }
    if (!s_desc[fd].ssh_rb) {
        errno = EPIPE;
        return -1;
    }
    size_t item_size = 0;
    void *item = xRingbufferReceive(s_desc[fd].ssh_rb, &item_size, pdMS_TO_TICKS(s_config.recv_timeout_ms));
    if (!item) {
        errno = EAGAIN;
        return -1;
    }
    size_t n = item_size < size ? item_size : size;
    memcpy(dst, item, n);
    vRingbufferReturnItem(s_desc[fd].ssh_rb, item);
    return n;
}

static int ssh_vfs_open(void* ctx, const char * path, int flags, int mode)
{
    if (path[0] != '/') {
        errno = ENOENT;
        return -1;
    }
    int fd = strtol(path + 1, NULL, 10);
    if (fd < 0 || fd >= MAX_CLIENTS) {
        errno = ENOENT;
        return -1;
    }
    int res = -1;
    _lock_acquire(&s_lock);
    if (s_desc[fd].opened) {
        errno = EPERM;
    } else {
        s_desc[fd].opened = true;
        res = fd;
    }
    _lock_release(&s_lock);
    return res;
}

static int ssh_vfs_close(void* ctx, int fd)
{
    if (fd < 0 || fd >= MAX_CLIENTS) {
        errno = EBADF;
        return -1;
    }
    int res = -1;
    _lock_acquire(&s_lock);
    if (!s_desc[fd].opened) {
        errno = EBADF;
    } else {
        s_desc[fd].opened = false;
        res = 0;
    }
    _lock_release(&s_lock);
    return res;
}

static int ssh_vfs_fstat(void* ctx, int fd, struct stat * st)
{
    *st = (struct stat) { 0 };
    st->st_mode = S_IFCHR;
    return 0;
}

esp_err_t ssh_vfs_add_client(ssh_channel handle, int id)
{
    esp_err_t res = ESP_OK;
    _lock_acquire(&s_lock);
    if (s_desc[id].ssh_handle != NULL) {
        ESP_LOGE(TAG, "%s: id=%d already in use", __func__, id);
        res = ESP_ERR_INVALID_STATE;
    } else {
        s_desc[id].ssh_handle = handle;
        s_desc[id].opened = false;
        s_desc[id].ssh_rb = xRingbufferCreate(s_config.recv_buffer_size, RINGBUF_TYPE_BYTEBUF);
    }
    _lock_release(&s_lock);
    return res;
}

esp_err_t ssh_vfs_del_client(ssh_channel handle)
{
    esp_err_t res = ESP_ERR_INVALID_ARG;
    _lock_acquire(&s_lock);
    for (int id = 0; id < MAX_CLIENTS; ++id) {
        if (s_desc[id].ssh_handle == handle) {
            s_desc[id].ssh_handle = NULL;
            s_desc[id].opened = false;
            if (s_desc[id].ssh_rb) {
                vRingbufferDelete(s_desc[id].ssh_rb);
                s_desc[id].ssh_rb = NULL;
            }
            res = ESP_OK;
            break;
        }
    }
    _lock_release(&s_lock);
    return res;
}
