//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Very simple HTTP server. Preload files in the given directory.
//
// Usage: ./app/httpd <link> <ipv4> <TCP port> <root dir>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include <algorithm>            // min()
#include <cstdio>
#include <cstdlib>
#include <cstring>              // strtok()

#include <alloca.h>             // alloca()
#include <dirent.h>             // struct dirent, opendir(), readdir()
#include <sys/stat.h>           // struct stat, stat()

#include "driver/cpu.hpp"
#include "driver/mpipe.hpp"
#include "util/macros.hpp"      // LIKELY(), UNLIKELY

using namespace std;

using namespace tcp_mpipe::driver;
using namespace tcp_mpipe::net;

#define HTTPD_COLOR     COLOR_GRN
#define HTTPD_DEBUG(MSG, ...)                                                  \
    TCP_MPIPE_DEBUG("HTTPD", HTTPD_COLOR, MSG, ##__VA_ARGS__)
#define HTTPD_ERROR(MSG, ...)                                                  \
    TCP_MPIPE_ERROR("HTTPD", HTTPD_COLOR, MSG, ##__VA_ARGS__)
#define HTTPD_DIE(MSG, ...)                                                    \
    TCP_MPIPE_DIE(  "HTTPD", HTTPD_COLOR, MSG, ##__VA_ARGS__)

// Parsed CLI arguments.
struct args_t {
    char                            *link_name;
    net_t<ipv4_addr_t>              ipv4_addr;
    mpipe_t::tcp_mpipe_t::port_t    tcp_port;
    char                            *root_dir;
};

// Type used to index file by their filename. Differents from 'std::string', so
// we can initialize it without having to reallocate and copy the string.
struct filename_t {
    const char                      *value;
};

namespace std {

// 'std::hash<>' and 'std::equal_to<>' instances are required to index
// files by their filenames.

template <>
struct hash<filename_t> {
    inline size_t operator()(filename_t filename) const
    {
        const char *str = filename.value;

        size_t sum = 0;
        while (*str != '\0') {
            sum += hash<char>()(*str);
            str++;
        }

        return sum;
    }
};

template <>
struct equal_to<filename_t> {
    inline bool operator()(filename_t a, filename_t b) const
    {
        return strcmp(a.value, b.value) == 0;
    }
};

} /* namespace std */

// Served file and its content.
struct file_t {
    const char                      *content;
    size_t                          content_len;
};

static void _print_usage(char **argv);

// Parses CLI arguments.
//
// Fails on a malformed command.
static bool _parse_args(int argc, char **argv, args_t *args);

// Loads all the file contents from the directory in the hash-table.
static void _preload_files(
    unordered_map<filename_t, file_t> *files, const char *dir
);

// Used to define empty event handlers.
static void _do_nothing(void);

// Interprets an HTTP request and serves the requested content.
static void _on_received_data(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id,
    unordered_map<filename_t, file_t> *files, mpipe_t::cursor_t in
);

// Responds to the client with a 200 OK HTTP response containing the given file.
void _respond_with_200(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id,
    const file_t *file
);

// Responds to the client with a 400 Bad Request HTTP response.
void _respond_with_400(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id
);

// Responds to the client with a 404 Not Found HTTP response.
void _respond_with_404(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id
);

int main(int argc, char **argv)
{
    args_t args;
    if (!_parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    cpu::bind_to_dataplane(0);

    mpipe_t mpipe(args.link_name, args.ipv4_addr);

    unordered_map<filename_t, file_t> files { };
    _preload_files(&files, args.root_dir);

    HTTPD_DEBUG(
        "Starts the HTTP server on interface %s (%s) with %s as IPv4 address "
        "on port %d serving %s",
        args.link_name,
        mpipe_t::ethernet_mpipe_t::addr_t::to_alpha(mpipe.data_link.addr),
        mpipe_t::ipv4_mpipe_t::addr_t::to_alpha(args.ipv4_addr), args.tcp_port,
        args.root_dir
    );

    mpipe.data_link.ipv4.tcp.listen(
        args.tcp_port,

        // On new connections.
        [tcp=&mpipe.data_link.ipv4.tcp, &files]
        (mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id) {
            HTTPD_DEBUG(
                "New connection from %s:%" PRIu16 " on port %" PRIu16,
                mpipe_t::ipv4_mpipe_t::addr_t::to_alpha(tcb_id.raddr),
                tcb_id.rport.host(), tcb_id.lport.host()
            );

            return (mpipe_t::tcp_mpipe_t::conn_handlers_t) {
                [tcp, tcb_id, &files](mpipe_t::cursor_t in)
                {
                    _on_received_data(tcp, tcb_id, &files, in);
                },

                [tcp, tcb_id]()
                {
                    // Closes when the remote closes the connection.
//                     tcp->close(tcb_id);
                },

                _do_nothing, _do_nothing
            };
        }
    );

    // Runs the application.
    mpipe.run();

    mpipe.close();

    return EXIT_SUCCESS;
}

static void _print_usage(char **argv)
{
    fprintf(stderr, "Usage: %s <link> <ipv4> <TCP port> <root dir>\n", argv[0]);
}

static bool _parse_args(int argc, char **argv, args_t *args)
{
    if (argc != 5) {
        _print_usage(argv);
        return false;
    }

    args->link_name = argv[1];

    struct in_addr in_addr;
    if (inet_aton(argv[2], &in_addr) != 1) {
        fprintf(stderr, "Failed to parse the IPv4.\n");
        _print_usage(argv);
        return false;
    }
    args->ipv4_addr = ipv4_addr_t::from_in_addr(in_addr);

    args->tcp_port = atoi(argv[3]);

    args->root_dir = argv[4];

    return true;
}

static void _preload_files(
    unordered_map<filename_t, file_t> *files, const char *root_dir
)
{
    DIR *dir;

    if (!(dir = opendir(root_dir)))
        HTTPD_DIE("Unable to open the directory");

    struct dirent *entry;

    size_t root_dir_len = strlen(root_dir);

    while ((entry = readdir(dir))) {
        filename_t filename = { strdup(entry->d_name) };

        // Filename with the directory path.
        char *filepath = new char[root_dir_len + strlen(filename.value) + 2];
        strcpy(filepath, root_dir);
        filepath[root_dir_len] = '/';
        strcpy(filepath + root_dir_len + 1, filename.value);

        // Skips directories.
        struct stat stat_buffer;
        if (stat(filepath, &stat_buffer) != 0)
            HTTPD_DIE("Unable to get info on a file (%s)", filename.value);
        if (S_ISDIR(stat_buffer.st_mode))
            continue;

        FILE *file;
        if (!(file = fopen(filepath, "r")))
            HTTPD_DIE("Unable to open a file");

        // Obtains the size of the file
        fseek(file, 0, SEEK_END);
        size_t content_len = ftell(file);
        fseek(file, 0, SEEK_SET);

        // Reads the file content

        char *content = new char[content_len + 1];
        size_t read = fread(content, 1, content_len, file);

        if (read != content_len)
            HTTPD_DIE("Unable to read a file %zu %zu", read, content_len);

        content[content_len] = '\0';

        fclose(file);

        file_t entry = { content, content_len };
        files->emplace(filename, entry);
    }

    HTTPD_DEBUG("%zu file(s) preloaded", files->size());
}

static void _do_nothing(void)
{
}

static void _on_received_data(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id,
    unordered_map<filename_t, file_t> *files, mpipe_t::cursor_t in
)
{
    // Expects that the first received segment contains the entire request.

    size_t size = in.size();

    #define BAD_REQUEST(WHY, ...)                                              \
        do {                                                                   \
            HTTPD_ERROR("400 Bad Request (" WHY ")", ##__VA_ARGS__);           \
            _respond_with_400(tcp, tcb_id);                                    \
            tcp->close(tcb_id);                                                \
            return;                                                            \
        } while (0)

    if (UNLIKELY(size < sizeof ("XXX / HTTP/X.X\n")))
        BAD_REQUEST("Not enough received data for the HTTP header");

    in.read_with(
        [tcp, tcb_id, files](const char *buffer)
        {
            //
            // Extracts the filename from the HTTP header
            //

            size_t      get_len         = sizeof ("GET /") - sizeof ('\0');

            if (UNLIKELY(strncmp(buffer, "GET /", get_len) != 0))
                BAD_REQUEST("Not a GET request");

            const char  *path_begin     = buffer + get_len;
            const char  *path_end       = strchr(path_begin, ' ');

            const char  *http11_begin   = path_end + 1;
            size_t      http11_len      = sizeof ("HTTP/1.1") - sizeof ('\0');
            const char  *http11_end     = http11_begin + http11_len;


            if (UNLIKELY(strncmp(http11_begin, "HTTP/1.1", http11_len) != 0))
                BAD_REQUEST("Not HTTP 1.1");

            if (UNLIKELY(http11_end[0] != '\n' && http11_end[0] != '\r'))
                BAD_REQUEST("Invalid header");

            size_t  path_len    = (intptr_t) path_end - (intptr_t) path_begin;
            char    *path       = (char *) alloca(path_len);
            strncpy(path, path_begin, path_len);

            //
            // Responds to the request.
            //

            auto file_it = files->find({ path });

            if (LIKELY(file_it != files->end())) {
                HTTPD_DEBUG("200 OK - \"%s\"", path);
                _respond_with_200(tcp, tcb_id, &file_it->second);
            } else {
                HTTPD_DEBUG("404 Not Found - \"%s\"", path);
                _respond_with_404(tcp, tcb_id);
            }

            tcp->close(tcb_id);
        }, size
    );

    #undef BAD_REQUEST
}

void _respond_with_200(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id,
    const file_t *file
)
{
    constexpr char header[]     = "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: text/html\r\n"
                                  "Content-Length: %10zu\r\n"
                                  "\r\n";

    constexpr size_t header_len =   sizeof (header) - sizeof ('\0')
                                  - sizeof ("%10zu")
                                  + sizeof ("4294967295");

    size_t total_len = header_len + file->content_len;

    tcp->send(
        tcb_id, total_len,
        [file](size_t offset, mpipe_t::cursor_t out)
        {
            size_t content_offset;

            // Writes the HTTP header if required.
            if (offset < header_len) {
                char buffer[header_len + 1];

                snprintf(buffer, sizeof buffer, header, file->content_len);

                size_t to_write = min(out.size(), header_len - offset);

                out            = out.write(buffer + offset, to_write);
                content_offset = 0;
            } else
                content_offset = offset - header_len;

            // Writes the file content if required.
            size_t out_size = out.size();
            if (out_size > 0) {
                assert(out_size <= file->content_len - content_offset);
                out.write(file->content + content_offset, out_size);
            }
        },
        _do_nothing /* Does nothing on ACK */
    );
}

#define RESPOND_WITH_CONTENT(CONTENT)                                          \
    do {                                                                       \
        constexpr char status[] = CONTENT;                                     \
                                                                               \
        tcp->send(                                                             \
            tcb_id, sizeof (status) - 1,                                       \
            [](size_t offset, mpipe_t::cursor_t out)                           \
            {                                                                  \
                out.write(status + offset, out.size());                        \
            }, _do_nothing                                                     \
        );                                                                     \
    } while (0);

void _respond_with_400(
    mpipe_t::tcp_mpipe_t*tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id
)
{
    RESPOND_WITH_CONTENT("HTTP/1.1 400 Bad Request\r\n\r\n");
}

void _respond_with_404(
    mpipe_t::tcp_mpipe_t *tcp, mpipe_t::tcp_mpipe_t::tcb_id_t tcb_id
)
{
    RESPOND_WITH_CONTENT("HTTP/1.1 400 Bad Request\r\n\r\n");
}

#undef RESPOND_WITH_CONTENT

#undef HTTPD_COLOR
#undef HTTPD_DEBUG
#undef HTTPD_DIE
