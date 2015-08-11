//
// Very simple HTTP server. Preload files from the given directory.
//
// Usage: ./app/httpd <link> <ipv4> <TCP port> <root dir> <n workers>
//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
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
#include <cstring>
#include <unordered_map>
#include <vector>

#include <alloca.h>             // alloca()
#include <dirent.h>             // struct dirent, opendir(), readdir()
#include <sys/stat.h>           // struct stat, stat()

#include <tmc/mem.h>            // tmc_mem_prefetch()

#include "driver/cpu.hpp"
#include "driver/mpipe.hpp"
#include "net/checksum.hpp"     // partial_sum_t, precomputed_sums_t
#include "net/endian.hpp"       // net_t
#include "util/macros.hpp"      // LIKELY(), UNLIKELY, RUSTY_*

using namespace std;

using namespace rusty::driver;
using namespace rusty::net;

#define USE_PRECOMPUTED_CHECKSUMS

static mpipe_t::arp_ipv4_t::static_entry_t
_static_arp_entry(const char *ipv4_addr_char, const char *ether_addr_char);

static vector<mpipe_t::arp_ipv4_t::static_entry_t> static_arp_entries {
    // eth2 frodo.run.montefiore.ulg.ac.be
    _static_arp_entry("10.0.2.1", "90:e2:ba:46:f2:d4"),

    // eth3 frodo.run.montefiore.ulg.ac.be
    _static_arp_entry("10.0.3.1", "90:e2:ba:46:f2:d5"),

    // eth4 frodo.run.montefiore.ulg.ac.be
    _static_arp_entry("10.0.4.1", "90:e2:ba:46:f2:e0"),

    // eth5 frodo.run.montefiore.ulg.ac.be
    _static_arp_entry("10.0.5.1", "90:e2:ba:46:f2:e1")
};

#define HTTPD_COLOR     COLOR_GRN
#define HTTPD_DEBUG(MSG, ...)                                                  \
    RUSTY_DEBUG("HTTPD", HTTPD_COLOR, MSG, ##__VA_ARGS__)
#define HTTPD_ERROR(MSG, ...)                                                  \
    RUSTY_ERROR("HTTPD", HTTPD_COLOR, MSG, ##__VA_ARGS__)
#define HTTPD_DIE(MSG, ...)                                                    \
    RUSTY_DIE(  "HTTPD", HTTPD_COLOR, MSG, ##__VA_ARGS__)

// Parsed CLI arguments.
struct args_t {
    struct interface_t {
        char                            *link_name;
        net_t<mpipe_t::ipv4_t::addr_t>  ipv4_addr;
        size_t                          n_workers;
    };

    mpipe_t::tcp_t::port_t          tcp_port;
    char                            *root_dir;
    vector<interface_t>             interfaces;
};

// Type used to index file by their filename. Different from 'std::string', so
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

    #ifdef USE_PRECOMPUTED_CHECKSUMS
        precomputed_sums_t              precomputed_sums;
    #endif /* USE_PRECOMPUTED_CHECKSUMS */
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
    unordered_map<filename_t, file_t> *files, mpipe_t::tcp_t::conn_t conn,
    mpipe_t::cursor_t in
);

// Responds to the client with a 200 OK HTTP response containing the given file.
void _respond_with_200(mpipe_t::tcp_t::conn_t conn, const file_t *file);

// Responds to the client with a 400 Bad Request HTTP response.
void _respond_with_400(mpipe_t::tcp_t::conn_t conn);

// Responds to the client with a 404 Not Found HTTP response.
void _respond_with_404(mpipe_t::tcp_t::conn_t conn);

int main(int argc, char **argv)
{
    args_t args;
    if (!_parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    unordered_map<filename_t, file_t> files { };
    _preload_files(&files, args.root_dir);

    //
    // Handler executed on new connections.
    //

    auto on_new_connection =
        [&files](mpipe_t::tcp_t::conn_t conn)
        {
            HTTPD_DEBUG(
                "New connection from %s:%" PRIu16 " on port %" PRIu16,
                mpipe_t::ipv4_t::addr_t::to_alpha(conn.tcb_id.raddr),
                conn.tcb_id.rport.host(), conn.tcb_id.lport.host()
            );

            mpipe_t::tcp_t::conn_handlers_t handlers;

            handlers.new_data =
                [&files, conn](mpipe_t::cursor_t in) mutable
                {
                    if (conn.can_send())
                        _on_received_data(&files, conn, in);
                };

            handlers.remote_close =
                [conn]() mutable
                {
                    // Closes when the remote closes the connection.
                    conn.close();
                };

            handlers.close = _do_nothing;

            handlers.reset = _do_nothing;

            return handlers;
        };

    //
    // Starts an mpipe instance for each interface.
    //

    vector<mpipe_t> instances;
    instances.reserve(args.interfaces.size());

    int first_dataplane_cpu = 0;
    for (args_t::interface_t &interface : args.interfaces) {
        instances.emplace_back(
            interface.link_name, interface.ipv4_addr, interface.n_workers,
            first_dataplane_cpu, static_arp_entries
        );

        mpipe_t &mpipe = instances.back();

        HTTPD_DEBUG(
            "Starts the HTTP server on interface %s (%s) with %s as IPv4 "
            "address on port %d serving %s",
            interface.link_name,
            mpipe_t::ethernet_t::addr_t::to_alpha(mpipe.ether_addr),
            mpipe_t::ipv4_t::addr_t::to_alpha(interface.link_name), 
            args.tcp_port, args.root_dir
        );

        mpipe.tcp_listen(args.tcp_port, on_new_connection);

        mpipe.run();

        first_dataplane_cpu += interface.n_workers;
    }

    // Wait for all instances to finish (will not happen).
    for (mpipe_t &mpipe_instance : instances)
        mpipe_instance.join();

    return EXIT_SUCCESS;
}

static mpipe_t::arp_ipv4_t::static_entry_t
_static_arp_entry(const char *ipv4_addr_char, const char *ether_addr_char)
{
    struct in_addr ipv4_addr;
    if (inet_aton(ipv4_addr_char, &ipv4_addr) != 1)
        HTTPD_DIE("Invalid IPv4 address");

    struct ether_addr *ether_addr;
    if ((ether_addr = ether_aton(ether_addr_char)) == nullptr)
        HTTPD_DIE("Invalid Ethernet address");

    return (mpipe_t::arp_ipv4_t::static_entry_t) {
        mpipe_t::ipv4_t::addr_t::from_in_addr(ipv4_addr),
        mpipe_t::ethernet_t::addr_t::from_ether_addr(ether_addr)
    };
}

static void _print_usage(char **argv)
{
    fprintf(
        stderr,
        "Usage: %s <TCP port> <root dir> <n links> "
        "[<link> <ipv4 of this link> <n workers on this link>]...\n",
        argv[0]
    );
}

static bool _parse_args(int argc, char **argv, args_t *args)
{
    if (argc < 4) {
        _print_usage(argv);
        return false;
    }

    args->tcp_port = atoi(argv[1]);

    args->root_dir = argv[2];

    int n_links = atoi(argv[3]);

    if (argc != 4 + n_links * 3){
        _print_usage(argv);
        return false;
    }

    args->interfaces.reserve(n_links);

    for (int i = 0; i < n_links; i++) {
        args_t::interface_t interface;

        interface.link_name = argv[4 + 3 * i];

        struct in_addr in_addr;
        if (inet_aton(argv[5 + 3 * i], &in_addr) != 1) {
            fprintf(stderr, "Failed to parse the IPv4.\n");
            _print_usage(argv);
            return false;
        }
        interface.ipv4_addr = ipv4_addr_t::from_in_addr(in_addr);

        interface.n_workers = atoi(argv[6 + 3 * i]);

        args->interfaces.push_back(interface);
    }

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
        size_t content_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        // Reads the file content

        char *content = new char[content_size + 1];
        size_t read = fread(content, 1, content_size, file);

        if (read != content_size)
            HTTPD_DIE("Unable to read a file %zu %zu", read, content_size);

        content[content_size] = '\0';

        fclose(file);

        #ifdef USE_PRECOMPUTED_CHECKSUMS
            file_t entry = {
                content, content_size, precomputed_sums_t(content, content_size)
            };
        #else
            file_t entry = { content, content_size };
        #endif /* USE_PRECOMPUTED_CHECKSUMS */

        files->emplace(filename, entry);
    }

    HTTPD_DEBUG("%zu file(s) preloaded", files->size());
}

static void _do_nothing(void)
{
}

static void _on_received_data(
    unordered_map<filename_t, file_t> *files, mpipe_t::tcp_t::conn_t conn,
    mpipe_t::cursor_t in
)
{
    // Expects that the first received segment contains the entire request.

    size_t size = in.size();

    #define BAD_REQUEST(WHY, ...)                                              \
        do {                                                                   \
            HTTPD_ERROR("400 Bad Request (" WHY ")", ##__VA_ARGS__);           \
            _respond_with_400(conn);                                           \
            conn.close();                                                      \
            return;                                                            \
        } while (0)

    if (UNLIKELY(size < sizeof ("XXX / HTTP/X.X\n")))
        BAD_REQUEST("Not enough received data for the HTTP header");

    in.read_with(
        [files, conn](const char *buffer) mutable
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
            path[path_len] = '\0';

            //
            // Responds to the request.
            //

            auto file_it = files->find({ path });

            if (LIKELY(file_it != files->end())) {
                HTTPD_DEBUG("200 OK - \"%s\"", path);
                _respond_with_200(conn, &file_it->second);
            } else {
                HTTPD_ERROR("404 Not Found - \"%s\"", path);
                _respond_with_404(conn);
            }

            conn.close();
        }, size
    );

    #undef BAD_REQUEST
}

void _respond_with_200(mpipe_t::tcp_t::conn_t conn, const file_t *file)
{
    constexpr char header[]     = "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: text/html\r\n"
                                  "Content-Length: %10zu\r\n"
                                  "\r\n";

    constexpr size_t header_len =   sizeof (header) - sizeof ('\0')
                                  - sizeof ("%10zu")
                                  + sizeof ("4294967295");

    size_t total_len = header_len + file->content_len;

    #ifdef USE_PRECOMPUTED_CHECKSUMS
        mpipe_t::tcp_t::writer_sum_t writer =
    #else
        mpipe_t::tcp_t::writer_t writer =
    #endif /* USE_PRECOMPUTED_CHECKSUMS */
        [file](size_t offset, mpipe_t::cursor_t out)
        {
            size_t content_offset;

            #ifdef USE_PRECOMPUTED_CHECKSUMS
                partial_sum_t partial_sum;
            #endif /* USE_PRECOMPUTED_CHECKSUMS */

            // Writes the HTTP header if required.
            if (offset < header_len) {
                tmc_mem_prefetch(header, sizeof (header));

                char buffer[header_len + 1];

                snprintf(buffer, sizeof (buffer), header, file->content_len);

                size_t to_write = min(out.size(), header_len - offset);

                out            = out.write(buffer + offset, to_write);
                content_offset = 0;

                #ifdef USE_PRECOMPUTED_CHECKSUMS
                    partial_sum = partial_sum_t(buffer + offset, to_write);
                #endif /* USE_PRECOMPUTED_CHECKSUMS */
            } else {
                content_offset = offset - header_len;

                #ifdef USE_PRECOMPUTED_CHECKSUMS
                    partial_sum = partial_sum_t::ZERO;
                #endif /* USE_PRECOMPUTED_CHECKSUMS */
            }

            size_t out_size     = out.size();

            tmc_mem_prefetch(file->content + content_offset, out_size);

            #ifdef USE_PRECOMPUTED_CHECKSUMS
                size_t content_end  = content_offset + out_size;
                file->precomputed_sums.prefetch(content_offset, content_end);
            #endif /* USE_PRECOMPUTED_CHECKSUMS */

            // Writes the file content if required.
            if (out_size > 0) {
                assert(out_size <= file->content_len - content_offset);
                out.write(file->content + content_offset, out_size);
            }

            #ifdef USE_PRECOMPUTED_CHECKSUMS
                // Returns the precomputed checksum sums.
                return (partial_sum_t) partial_sum.append(
                    file->precomputed_sums.sum(content_offset, content_end)
                );
            #endif /* USE_PRECOMPUTED_CHECKSUMS */
        };

    conn.send(total_len, writer, _do_nothing /* Does nothing on ACK */);
}

#define RESPOND_WITH_CONTENT(CONTENT)                                          \
    do {                                                                       \
        constexpr char status[] = CONTENT;                                     \
                                                                               \
        conn.send(                                                             \
            sizeof (status) - 1,                                               \
            [](size_t offset, mpipe_t::cursor_t out)                           \
            {                                                                  \
                out.write(status + offset, out.size());                        \
            }, _do_nothing                                                     \
        );                                                                     \
    } while (0);

void _respond_with_400(mpipe_t::tcp_t::conn_t conn)
{
    RESPOND_WITH_CONTENT("HTTP/1.1 400 Bad Request\r\n\r\n");
}

void _respond_with_404(mpipe_t::tcp_t::conn_t conn)
{
    RESPOND_WITH_CONTENT("HTTP/1.1 404 Not Found\r\n\r\n");
}

#undef RESPOND_WITH_CONTENT

#undef HTTPD_COLOR
#undef HTTPD_DEBUG
#undef HTTPD_DIE
