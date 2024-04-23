////////////////////////////////////////////////////////////////////////////////
// MIT License                                                                //
//                                                                            //
// Copyright (c) 2024 Erich Erstu                                             //
//                                                                            //
// Permission is hereby granted, free of charge, to any person obtaining a    //
// copy of this software and associated documentation files (the "Software"), //
// to deal in the Software without restriction, including without limitation  //
// the rights to use, copy, modify, merge, publish, distribute, sublicense,   //
// and/or sell copies of the Software, and to permit persons to whom the      //
// Software is furnished to do so, subject to the following conditions:       //
//                                                                            //
// The above copyright notice and this permission notice shall be included in //
// all copies or substantial portions of the Software.                        //
//                                                                            //
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR //
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   //
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    //
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER //
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING    //
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER        //
// DEALINGS IN THE SOFTWARE.                                                  //
////////////////////////////////////////////////////////////////////////////////

#ifndef DATABUS_H_17_04_2024
#define DATABUS_H_17_04_2024

#include <algorithm>
#include <limits>

#include <csignal>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <cstdio>

class DATABUS final {
    public:
    static constexpr const char *const VERSION = "0.00";

    enum class ERROR : unsigned char {
        NONE = 0,
        LIBRARY,       // There is a bug in this library.
        BAD_REQUEST,   // There is a bug in the caller's application.
        SYSTEM,        // Standard Library's system call failed with an error.
        PENDING_ALERT, // Handle all the pending alerts and try again.
        OUT_OF_MEMORY, // Free some memory and then try again.
        UNKNOWN        // Standard Library call failed for an unknown reason.
    };

    static constexpr const ERROR
        NO_ERROR       = ERROR::NONE,
        LIBRARY_ERROR  = ERROR::LIBRARY,
        BAD_REQUEST    = ERROR::BAD_REQUEST,
        SYSTEM_ERROR   = ERROR::SYSTEM,
        PENDING_ALERT  = ERROR::PENDING_ALERT,
        OUT_OF_MEMORY  = ERROR::OUT_OF_MEMORY,
        UNKNOWN_ERROR  = ERROR::UNKNOWN;

    static constexpr const char *to_string(ERROR) noexcept;

    struct ENTRY {
        size_t id;
        size_t size;
        const void *data;
        const char *c_str;
        ERROR error;
        bool valid:1;
    };

    enum class EVENT : unsigned char {
        NONE = 0,
        // Do not change the list above this line.
        SYNCHRONIZE,
        DESERIALIZE,
        SERIALIZE,
        // Do not change the list below this line.
        MAX_EVENTS
    };

    static constexpr const EVENT
        NO_EVENT    = EVENT::NONE,
        SYNCHRONIZE = EVENT::SYNCHRONIZE,
        DESERIALIZE = EVENT::DESERIALIZE,
        SERIALIZE   = EVENT::SERIALIZE;

    struct ALERT {
        size_t bus;
        EVENT event;
        bool valid:1;
    };

    struct RESULT{
        int        value;
        int         code;
        const char *text;
        const char *call;
        const char *file;
        int         line;
        ERROR      error;
    };

    DATABUS() noexcept;
    ~DATABUS();

    bool init() noexcept;
    bool deinit() noexcept;

    void set_logger(void (*callback)(ERROR, const char *) noexcept) noexcept;
    void set_memcap(size_t bytes) noexcept;
    size_t get_memcap() const noexcept;
    size_t get_memtop() const noexcept;

    ERROR next_error() noexcept;
    ERROR last_error() noexcept;
    ALERT next_alert() noexcept;

    size_t peek(const char **buf =nullptr) const noexcept;
    size_t read(void *buf, size_t count) noexcept;
    ERROR write(const void *buf, size_t count) noexcept;

    ERROR set_entry(size_t id, const void *data, size_t size) noexcept;
    ERROR set_entry(size_t id, const char *c_str) noexcept;
    ENTRY get_entry(size_t id) const noexcept;

    static constexpr const size_t BITS_PER_BYTE{
        std::numeric_limits<unsigned char>::digits
    };

    private:
    struct MEMORY {
        size_t     size;
        void      *data;
        MEMORY    *next;
        MEMORY    *prev;
        bool  indexed:1;
        bool recycled:1;
    };

    struct KEY {
        uintptr_t value;
    };

    struct PIPE {
        enum class TYPE : uint8_t {
            NONE = 0,
            UINT8,
            C_STR,
            UINT64,
            PTR,
            BUS_PTR,
            MEMORY_PTR,
            KEY
        };

        struct ENTRY {
            union {
                uint8_t  as_uint8;
                char     as_char;
                uint64_t as_uint64;
                void    *as_ptr;
                KEY      as_key;
            };
            TYPE type;
        };

        size_t capacity;
        size_t size;
        void *data;
        TYPE type;
        MEMORY *memory;
    };

    struct INDEX {
        enum class TYPE : uint8_t {
            NONE = 0,
            // Do not change the order of the types above this line.
            EVENT_TO_BUS,
            ID_TO_BUS,
            RESOURCE_TO_MEMORY,
            // Do not change the order of the types below this line.
            MAX_TYPES
        };

        struct ENTRY {
            PIPE *key_pipe;
            PIPE *val_pipe;
            size_t index;
            ERROR error;
            bool valid:1;
        };

        size_t buckets;
        size_t entries;
        struct TABLE {
            PIPE key;
            PIPE value;
        } *table;
        TYPE type;
        bool multimap:1;
        bool autogrow:1;
    };

    struct BUS {
        size_t id;
        ssize_t event_lookup[ static_cast<size_t>(EVENT::MAX_EVENTS) ];
        PIPE payload;
        /*
        PIPE contents;
        struct CONTAINER {
            size_t content_id;
            size_t content_index;
        } container;
        */
    };

    struct QUERY {
        enum class TYPE : uint8_t {
            BUS_BY_ID,
            BUS_BY_EVENT
        };

        union {
            size_t bus_id;
            EVENT  bus_event;
        };
        TYPE type;
    };

    static constexpr KEY make_key(uintptr_t) noexcept;
    static constexpr KEY make_key(EVENT) noexcept;
    static constexpr struct BUS make_bus(
        size_t id, PIPE pipe =make_pipe(PIPE::TYPE::C_STR)
    ) noexcept;

    static constexpr struct ALERT make_alert(
        size_t bus, EVENT type, bool valid =true
    ) noexcept;

    static constexpr struct ENTRY make_entry(ERROR) noexcept;
    static constexpr struct ENTRY make_entry(
        size_t id, size_t size, void *data,
        ERROR error =ERROR::NONE, bool valid =true
    ) noexcept;

    static constexpr struct INDEX::ENTRY make_index_entry(
        PIPE &keys, PIPE &values, size_t index, ERROR, bool valid
    ) noexcept;

    static constexpr struct INDEX::ENTRY make_index_entry(
        PIPE &keys, PIPE &values, size_t index, ERROR
    ) noexcept;

    static constexpr PIPE make_pipe(
        const void *data, size_t size, PIPE::TYPE =PIPE::TYPE::UINT8
    ) noexcept;

    static constexpr PIPE make_pipe(PIPE::TYPE) noexcept;

    static constexpr PIPE::ENTRY make_pipe_entry(PIPE::TYPE) noexcept;
    static constexpr PIPE::ENTRY make_pipe_entry(uint64_t  ) noexcept;
    static constexpr PIPE::ENTRY make_pipe_entry(int       ) noexcept;
    static constexpr PIPE::ENTRY make_pipe_entry(KEY       ) noexcept;
    static constexpr PIPE::ENTRY make_pipe_entry(BUS *     ) noexcept;
    static constexpr PIPE::ENTRY make_pipe_entry(MEMORY *  ) noexcept;

    static constexpr QUERY make_query_by_id(size_t) noexcept;
    static constexpr QUERY make_query_by_event(EVENT) noexcept;

    static constexpr EVENT next(EVENT) noexcept;
    static constexpr size_t size(PIPE::TYPE) noexcept;
    static constexpr size_t align(PIPE::TYPE) noexcept;
    static constexpr auto fmt_bytes(size_t) noexcept;
    static constexpr const char *LEAF(const char *path) noexcept;
    static constexpr const char *TAIL(const char *, char neck) noexcept;
    static int clz(unsigned int) noexcept;
    static int clz(unsigned long) noexcept;
    static int clz(unsigned long long) noexcept;
    static unsigned int       next_pow2(unsigned int) noexcept;
    static unsigned long      next_pow2(unsigned long) noexcept;
    static unsigned long long next_pow2(unsigned long long) noexcept;

    [[nodiscard]] ERROR capture(const BUS &copy) noexcept;
    void release(BUS *) noexcept;

    BUS *find_bus(const QUERY &) const noexcept;
    BUS &get_bus(const QUERY &) const noexcept;
    const PIPE *find_buses(EVENT) const noexcept;

    void set_event(BUS &, EVENT, bool val =true) noexcept;
    void rem_event(BUS &, EVENT) noexcept;
    [[nodiscard]] bool has_event(const BUS &, EVENT) const noexcept;
    void rem_content(BUS &container, BUS &content) const noexcept;

    size_t count(INDEX::TYPE, KEY key) const noexcept;
    INDEX::ENTRY find(
        INDEX::TYPE, KEY key, PIPE::ENTRY value ={},
        size_t start_i =std::numeric_limits<size_t>::max(),
        size_t iterations =std::numeric_limits<size_t>::max()
    ) const noexcept;
    size_t erase(
        INDEX::TYPE, KEY key, PIPE::ENTRY value ={},
        size_t start_i =std::numeric_limits<size_t>::max(),
        size_t iterations =std::numeric_limits<size_t>::max()
    ) noexcept;
    [[nodiscard]] ERROR reserve(INDEX::TYPE, KEY key, size_t capacity) noexcept;
    [[nodiscard]] INDEX::ENTRY insert(
        INDEX::TYPE, KEY key, PIPE::ENTRY value
    ) noexcept;
    [[nodiscard]] ERROR reindex() noexcept;
    void erase(PIPE &pipe, size_t index) const noexcept;
    void destroy(PIPE &pipe) noexcept;
    void set_value(INDEX::ENTRY, PIPE::ENTRY) noexcept;
    PIPE::ENTRY get_value(INDEX::ENTRY) const noexcept;
    PIPE::ENTRY get_entry(const PIPE &pipe, size_t index) const noexcept;
    PIPE::ENTRY get_last(const PIPE &pipe) const noexcept;
    PIPE::ENTRY pop_back(PIPE &pipe) const noexcept;
    [[nodiscard]] ERROR reserve(PIPE&, size_t capacity) noexcept;
    [[nodiscard]] ERROR insert(PIPE&, PIPE::ENTRY) noexcept;
    [[nodiscard]] ERROR insert(PIPE&, size_t index, PIPE::ENTRY) noexcept;
    [[nodiscard]] ERROR copy(const PIPE &src, PIPE &dst) noexcept;
    [[nodiscard]] ERROR append(const PIPE &src, PIPE &dst) noexcept;
    [[nodiscard]] ERROR null_terminate(PIPE &) noexcept;
    void null_terminate(PIPE &) const noexcept;
    void replace(PIPE&, size_t index, PIPE::ENTRY) const noexcept;
    INDEX &get_index(INDEX::TYPE) noexcept;

    KEY       to_key   (PIPE::ENTRY) const noexcept;
    BUS      *to_bus   (PIPE::ENTRY) const noexcept;
    MEMORY   *to_memory(PIPE::ENTRY) const noexcept;
    int       to_int   (PIPE::ENTRY) const noexcept;
    uint64_t  to_uint64(PIPE::ENTRY) const noexcept;

    int      *to_int   (const PIPE &) const noexcept;
    char     *to_char  (const PIPE &) const noexcept;
    uint8_t  *to_uint8 (const PIPE &) const noexcept;
    uint64_t *to_uint64(const PIPE &) const noexcept;
    KEY      *to_key   (const PIPE &) const noexcept;
    void    **to_ptr   (const PIPE &) const noexcept;

    void *to_ptr(PIPE::ENTRY &) const noexcept;
    void *to_ptr(PIPE &, size_t index) const noexcept;
    const void *to_ptr(const PIPE &, size_t index) const noexcept;

    void enlist(MEMORY &, MEMORY *&list) noexcept;
    void unlist(MEMORY &, MEMORY *&list) noexcept;
    const MEMORY *find_memory(const void *) const noexcept;
    MEMORY *find_memory(const void *) noexcept;
    const MEMORY &get_memory(const void *) const noexcept;
    MEMORY &get_memory(const void *) noexcept;
    [[nodiscard]] INDEX::TABLE *allocate_tables(size_t count) noexcept;
    void destroy_and_delete(INDEX::TABLE *tables, size_t count) noexcept;
    [[nodiscard]] MEMORY *allocate_and_index(
        size_t byte_count, size_t alignment, const void *copy =nullptr
    ) noexcept;
    [[nodiscard]] MEMORY *allocate(const size_t bytes, size_t align) noexcept;
    void deallocate(MEMORY &) noexcept;
    void recycle(MEMORY &) noexcept;
    [[nodiscard]] BUS *new_bus(const BUS &copy) noexcept;

    ERROR report(
        ERROR, const char *fmt, ...
    ) const noexcept __attribute__((format(printf, 3, 4)));
    template<class... Args>
    void log(const char *fmt, Args&&... args) const noexcept {
        report(ERROR::NONE, fmt, std::forward<Args>(args)...);
    }
    ERROR report(
        ERROR,
        int line =__builtin_LINE(), const char *file =LEAF(__builtin_FILE()),
        char const *function = __builtin_FUNCTION()
    ) const noexcept;
    ERROR report(
        ERROR, int code, char const *function, const char *message,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;
    ERROR report_bug(
        const char *comment =nullptr,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;
    ERROR report_bad_request(
        const char *comment =nullptr,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;
    ERROR report_memory_exhaustion(
        const char *comment =nullptr,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;
    const RESULT &report(const RESULT &) noexcept;
    bool fuse(
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;
    [[noreturn]] void die(
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;

    static constexpr RESULT make_result(
        int value, int, ERROR,
        const char *comment, const char *function, const char *file, int line
    ) noexcept;

    RESULT call_sigfillset(
        sigset_t *set,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    RESULT call_sigemptyset(
        sigset_t *set,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    RESULT call_pthread_sigmask(
        int how, const sigset_t *set, sigset_t *oldset,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;

    void clear() noexcept;
    ERROR err(ERROR) noexcept;

    void (*log_callback)(ERROR, const char *text) noexcept;
    INDEX indices[static_cast<size_t>(INDEX::TYPE::MAX_TYPES)];

    struct MEMPOOL {
        MEMORY *free[sizeof(size_t) * BITS_PER_BYTE];
        MEMORY *list;
        size_t usage;
        size_t top;
        size_t cap;
        bool   oom:1;
    } mempool;

    static constexpr struct MEMPOOL make_mempool() noexcept;

    EVENT handled;
    ERROR errored;

    size_t bus_count;

    struct BITSET {
        bool alerted:1;
        bool reindex:1;
    } bitset;

    sigset_t sigset_all;
    sigset_t sigset_none;

    public:
    mutable uint8_t fuses[768];
};

inline bool operator!(DATABUS::ERROR error) noexcept {
    return error == static_cast<DATABUS::ERROR>(0);
}

inline bool operator!(DATABUS::RESULT result) noexcept {
    return result.error != DATABUS::ERROR::NONE || result.code != 0;
}

inline DATABUS::DATABUS() noexcept :
    log_callback(nullptr), indices{}, mempool{make_mempool()}, handled{},
    errored{}, bus_count{}, bitset{}, sigset_all{}, sigset_none{}, fuses{} {
}

inline DATABUS::~DATABUS() {
    if (mempool.usage > sizeof(DATABUS)) {
        log(
            "memory usage remains at %lu byte%s (leak?)",
            mempool.usage, mempool.usage == 1 ? "" : "s"
        );
    }

    for (INDEX &index : indices) {
        if (index.type == INDEX::TYPE::NONE) {
            continue;
        }

        log(
            "%s\n", "destroying instance without having it deinitialized first"
        );

        break;
    }
}

inline void DATABUS::clear() noexcept {
    errored = ERROR::NONE;
    handled = EVENT::NONE;

    for (INDEX &index : indices) {
        if (index.table) {
            destroy_and_delete(index.table, index.buckets);
            index.table = nullptr;
        }

        index.buckets = 0;
        index.entries = 0;
        index.type = INDEX::TYPE::NONE;
    }

    if (mempool.list) {
        report_bug(
            // We should have already explicitly deallocated all memory.
        );

        while (mempool.list) {
            deallocate(*mempool.list);
        }
    }

    for (MEMORY *&free : mempool.free) {
        while (free) {
            deallocate(*free);
        }
    }

    mempool.usage = sizeof(DATABUS);
    mempool.top = mempool.usage;

    bus_count = 0;
    bitset = {};

    std::fill(fuses, fuses+sizeof(fuses), 0);
}

inline bool DATABUS::init() noexcept {
    for (INDEX &index : indices) {
        if (index.type != INDEX::TYPE::NONE) {
            log("%s: already initialized", __FUNCTION__);

            return false;
        }
    }

    if (!report(call_sigfillset(&sigset_all))
    ||  !report(call_sigemptyset(&sigset_none))) {
        return false;
    }

    clear();

    for (INDEX &index : indices) {
        index.type = static_cast<INDEX::TYPE>(&index - &indices[0]);

        switch (index.type) {
            default: {
                index.buckets = 1;
                index.multimap = false;
                index.autogrow = true;
                break;
            }
            case INDEX::TYPE::EVENT_TO_BUS: {
                index.buckets = static_cast<size_t>(EVENT::MAX_EVENTS);
                index.multimap = true;
                index.autogrow = false;
                break;
            }
        }

        switch (index.type) {
            case INDEX::TYPE::NONE: continue;
            case INDEX::TYPE::EVENT_TO_BUS:
            case INDEX::TYPE::ID_TO_BUS:
            case INDEX::TYPE::RESOURCE_TO_MEMORY: {
                index.table = allocate_tables(index.buckets);
                break;
            }
            default: die();
        }

        if (index.table == nullptr) {
            report_memory_exhaustion();
            clear();
            return false;
        }

        for (size_t j=0; j<index.buckets; ++j) {
            INDEX::TABLE &table = index.table[j];
            PIPE &key_pipe = table.key;
            PIPE &val_pipe = table.value;

            key_pipe.type = PIPE::TYPE::KEY;

            switch (index.type) {
                case INDEX::TYPE::ID_TO_BUS: {
                    val_pipe.type = PIPE::TYPE::BUS_PTR;
                    break;
                }
                case INDEX::TYPE::RESOURCE_TO_MEMORY: {
                    val_pipe.type = PIPE::TYPE::MEMORY_PTR;
                    break;
                }
                case INDEX::TYPE::EVENT_TO_BUS: {
                    val_pipe.type = PIPE::TYPE::BUS_PTR;
                    break;
                }
                default: die();
            }

            if (val_pipe.type == PIPE::TYPE::NONE) {
                clear();
                report_bug();
                return false;
            }
        }
    }

    return true;
}

inline bool DATABUS::deinit() noexcept {
    bool success = true;

    INDEX &id_to_bus = get_index(INDEX::TYPE::ID_TO_BUS);

    for (size_t bucket=0; bucket<id_to_bus.buckets; ++bucket) {
        while (id_to_bus.table[bucket].key.size) {
            BUS *const bus{to_bus(get_last(id_to_bus.table[bucket].value))};

            release(bus);
        }
    }

    clear();

    return success;
}

inline void DATABUS::set_logger(
    void (*callback)(ERROR, const char *) noexcept
) noexcept {
    log_callback = callback;
}

inline void DATABUS::set_memcap(size_t bytes) noexcept {
    mempool.cap = bytes;
}

inline size_t DATABUS::get_memcap() const noexcept {
    return mempool.cap;
}

inline size_t DATABUS::get_memtop() const noexcept {
    return mempool.top;
}

inline DATABUS::ERROR DATABUS::err(ERROR e) noexcept {
    return (errored = e);
}

inline DATABUS::ERROR DATABUS::last_error() noexcept {
    return errored;
}

constexpr auto DATABUS::fmt_bytes(size_t b) noexcept {
    constexpr const size_t one{1};
    struct format_type{
        double value;
        const char *unit;
    };

    return (
        (sizeof(b) * BITS_PER_BYTE > 40) && b > (one << 40) ? (
            format_type{
                double((long double)(b) / (long double)(one << 40)), "TiB"
            }
        ) :
        (sizeof(b) * BITS_PER_BYTE > 30) && b > (one << 30) ? (
            format_type{
                double((long double)(b) / (long double)(one << 30)), "GiB"
            }
        ) :
        (sizeof(b) * BITS_PER_BYTE > 20) && b > (one << 20) ? (
            format_type{ double(b) / double(one << 20), "MiB" }
        ) : format_type{ double(b) / double(one << 10), "KiB" }
    );
}

inline DATABUS::ERROR DATABUS::set_entry(
    size_t id, const void *data, size_t size
) noexcept {
    ERROR error = NO_ERROR;

    BUS *bus = find_bus(make_query_by_id(id));

    if (bus) {
        const PIPE payload_wrapper{make_pipe(data, size, PIPE::TYPE::C_STR)};

        error = copy(payload_wrapper, bus->payload);
    }
    else {
        const BUS copy_from{
            make_bus(id, make_pipe(data, size, PIPE::TYPE::C_STR))
        };

        error = capture(copy_from);
    }

    return error;
}

inline DATABUS::ERROR DATABUS::set_entry(
    size_t id, const char *data
) noexcept {
    return set_entry(id, data, std::strlen(data));
}

inline DATABUS::ENTRY DATABUS::get_entry(size_t id) const noexcept {
    const BUS *bus = find_bus(make_query_by_id(id));

    if (!bus) {
        return make_entry(ERROR::NONE);
    }

    return make_entry(bus->id, bus->payload.size, bus->payload.data);
}

inline const DATABUS::RESULT &DATABUS::report(const RESULT &result) noexcept {
    if (result.error != ERROR::NONE) {
        report(
            result.error, result.code, result.call, result.text, result.file,
            result.line
        );
    }

    return result;
}

inline DATABUS::ERROR DATABUS::report(
    ERROR error, int code, char const *function, const char *message,
    const char *file, int line
) const noexcept {
    return report(
        error, "%s: %d: %s (%s:%d)", function, code, message, file, line
    );
}

inline DATABUS::ERROR DATABUS::report_bug(
    const char *comment, const char *file, int line
) const noexcept {
    if (!comment) {
        comment = "forbidden condition met";
    }

    return report(ERROR::LIBRARY, "%s (%s:%d)", comment, file, line);
}

inline DATABUS::ERROR DATABUS::report_bad_request(
    const char *comment, const char *file, int line
) const noexcept {
    if (!comment) {
        comment = "invalid request received from caller";
    }

    return report(
        ERROR::BAD_REQUEST, "%s (%s:%d)", comment, file, line
    );
}

inline DATABUS::ERROR DATABUS::report_memory_exhaustion(
    const char *comment, const char *file, int line
) const noexcept {
    if (!comment) {
        comment = "Out Of Memory";
    }

    return report(
        ERROR::OUT_OF_MEMORY, "%s (%s:%d)", comment, file, line
    );
}

inline bool DATABUS::fuse(const char *file, int line) const noexcept {
    size_t i = (static_cast<size_t>(line) / BITS_PER_BYTE) % sizeof(fuses);

    switch (line % BITS_PER_BYTE) {
        case 0: if (fuses[i] & (1<<0)) return false; fuses[i] |= (1<<0); break;
        case 1: if (fuses[i] & (1<<1)) return false; fuses[i] |= (1<<1); break;
        case 2: if (fuses[i] & (1<<2)) return false; fuses[i] |= (1<<2); break;
        case 3: if (fuses[i] & (1<<3)) return false; fuses[i] |= (1<<3); break;
        case 4: if (fuses[i] & (1<<4)) return false; fuses[i] |= (1<<4); break;
        case 5: if (fuses[i] & (1<<5)) return false; fuses[i] |= (1<<5); break;
        case 6: if (fuses[i] & (1<<6)) return false; fuses[i] |= (1<<6); break;
        case 7: if (fuses[i] & (1<<7)) return false; fuses[i] |= (1<<7); break;
    }

    log("fuse blows in %s on line %d", file, line);

    return true;
}

inline void DATABUS::die(const char *file, int line) const noexcept {
    report_bug("fatal error", file, line);
    fflush(nullptr);
    std::abort();
}

inline DATABUS::ERROR DATABUS::report(
    ERROR error, const char *fmt, ...
) const noexcept {
    char stackbuf[256];
    char *bufptr = stackbuf;
    size_t bufsz = sizeof(stackbuf);

    sigset_t sigset_orig;

    call_pthread_sigmask(SIG_SETMASK, &sigset_all, &sigset_orig);

    for (size_t i=0; i<2 && bufptr; ++i) {
        std::va_list args;
        va_start(args, fmt);
        int cx = vsnprintf(bufptr, bufsz, fmt, args);
        va_end(args);

        if ((cx >= 0 && (size_t)cx < bufsz) || cx < 0) {
            if (log_callback) {
                log_callback(error, bufptr);
            }
            else {
                if (::write(STDERR_FILENO, bufptr, strlen(bufptr)) > 0) {
                    ::write(STDERR_FILENO, "\n", 1);
                }
            }

            break;
        }

        if (bufptr == stackbuf) {
            bufsz = cx + 1;
            bufptr = new (std::nothrow) char[bufsz];

            if (!bufptr) {
                static constexpr const char *const OOM = "Out Of Memory!";

                if (log_callback) {
                    log_callback(error, OOM);
                }
                else {
                    if (::write(STDERR_FILENO, OOM, strlen(OOM)) > 0) {
                        ::write(STDERR_FILENO, "\n", 1);
                    }
                }
            }
        }
        else {
            if (log_callback) {
                log_callback(error, bufptr);
            }
            else {
                if (::write(STDERR_FILENO, bufptr, strlen(bufptr)) > 0) {
                    ::write(STDERR_FILENO, "\n", 1);
                }
            }

            break;
        }
    }

    call_pthread_sigmask(SIG_SETMASK, &sigset_orig, nullptr);

    if (bufptr && bufptr != stackbuf) delete [] bufptr;

    return error;
}

inline DATABUS::ERROR DATABUS::capture(const BUS &copy) noexcept {
    if (find_bus(make_query_by_id(copy.id))) {
        return fuse() ? report_bug() : ERROR::LIBRARY;
    }

    for (auto &ev : copy.event_lookup) {
        ERROR error{
            reserve(
                INDEX::TYPE::EVENT_TO_BUS,
                make_key(static_cast<EVENT>(&ev - &(copy.event_lookup[0]))),
                bus_count + 1
            )
        };

        if (!error) {
            continue;
        }

        return error;
    }

    BUS *const bus = new_bus(make_bus(copy.id));

    if (!bus) {
        return ERROR::OUT_OF_MEMORY;
    }

    ERROR error = ERROR::NONE;

    for (;;) {
        {
            error = this->copy(copy.payload, bus->payload);

            if (error != ERROR::NONE) {
                break;
            }
        }

        {
            INDEX::ENTRY entry{
                insert(
                    INDEX::TYPE::ID_TO_BUS,
                    make_key(bus->id), make_pipe_entry(bus)
                )
            };

            if (!entry.valid) {
                error = entry.error;
                break;
            }
        }

        break;
    }

    if (!error) {
        ++bus_count;

        return ERROR::NONE;
    }

    release(bus);

    return error;
}

inline void DATABUS::release(BUS *bus) noexcept {
    if (!bus) {
        report_bug();
        return;
    }

    for (auto &ev : bus->event_lookup) {
        rem_event(*bus, static_cast<EVENT>(&ev - &(bus->event_lookup[0])));
    }

    destroy(bus->payload);

    if (erase(INDEX::TYPE::ID_TO_BUS, make_key(bus->id))) {
        --bus_count;
    }

    recycle(get_memory(bus));
}

inline DATABUS::BUS *DATABUS::find_bus(const QUERY &query) const noexcept {
    INDEX::ENTRY entry;

    switch (query.type) {
        case QUERY::TYPE::BUS_BY_ID: {
            entry = find(
                INDEX::TYPE::ID_TO_BUS, make_key(query.bus_id)
            );

            break;
        }
        case QUERY::TYPE::BUS_BY_EVENT: {
            entry = find(
                INDEX::TYPE::EVENT_TO_BUS, make_key(query.bus_event)
            );

            break;
        }
    }

    if (!entry.valid) {
        return nullptr;
    }

    return to_bus(get_entry(*entry.val_pipe, entry.index));
}

inline DATABUS::BUS &DATABUS::get_bus(const QUERY &query) const noexcept {
    BUS *const bus = find_bus(query);

    if (!bus) die();

    return *bus;
}

inline const DATABUS::PIPE *DATABUS::find_buses(EVENT ev) const noexcept {
    INDEX::ENTRY entry{find(INDEX::TYPE::EVENT_TO_BUS, make_key(ev))};

    if (entry.valid) {
        return entry.val_pipe;
    }

    return nullptr;
}

inline DATABUS::INDEX &DATABUS::get_index(INDEX::TYPE index_type) noexcept {
    size_t i = static_cast<size_t>(index_type);

    if (i >= std::extent<decltype(indices)>::value) die();

    return indices[i];
}

inline DATABUS::BUS *DATABUS::to_bus(PIPE::ENTRY entry) const noexcept {
    if (entry.type != PIPE::TYPE::BUS_PTR) die();

    return static_cast<BUS *>(entry.as_ptr);
}

inline DATABUS::MEMORY *DATABUS::to_memory(PIPE::ENTRY entry) const noexcept {
    if (entry.type != PIPE::TYPE::MEMORY_PTR) die();

    return static_cast<MEMORY *>(entry.as_ptr);
}

inline uint64_t DATABUS::to_uint64(PIPE::ENTRY entry) const noexcept {
    if (entry.type != PIPE::TYPE::UINT64) die();

    return entry.as_uint64;
}

inline DATABUS::KEY DATABUS::to_key(PIPE::ENTRY entry) const noexcept {
    if (entry.type != PIPE::TYPE::KEY) die();

    return entry.as_key;
}

inline uint8_t *DATABUS::to_uint8(const PIPE &pipe) const noexcept {
    if (pipe.type != PIPE::TYPE::UINT8) die();

    return static_cast<uint8_t *>(pipe.data);
}

inline char *DATABUS::to_char(const PIPE &pipe) const noexcept {
    if (pipe.type != PIPE::TYPE::C_STR) die();

    return static_cast<char *>(pipe.data);
}

inline uint64_t *DATABUS::to_uint64(const PIPE &pipe) const noexcept {
    if (pipe.type != PIPE::TYPE::UINT64) die();

    return static_cast<uint64_t *>(pipe.data);
}

inline DATABUS::KEY *DATABUS::to_key(const PIPE &pipe) const noexcept {
    if (pipe.type != PIPE::TYPE::KEY) die();

    return static_cast<KEY *>(pipe.data);
}

inline void **DATABUS::to_ptr(const PIPE &pipe) const noexcept {
    switch (pipe.type) {
        case PIPE::TYPE::PTR:
        case PIPE::TYPE::MEMORY_PTR:
        case PIPE::TYPE::BUS_PTR: {
            return static_cast<void **>(pipe.data);
        }
        case PIPE::TYPE::UINT8:
        case PIPE::TYPE::C_STR:
        case PIPE::TYPE::UINT64:
        case PIPE::TYPE::KEY:
        case PIPE::TYPE::NONE: {
            break;
        }
    }

    die();
}

inline void *DATABUS::to_ptr(PIPE::ENTRY &entry) const noexcept {
    switch (entry.type) {
        case PIPE::TYPE::PTR:
        case PIPE::TYPE::MEMORY_PTR:
        case PIPE::TYPE::BUS_PTR:     return &(entry.as_ptr);
        case PIPE::TYPE::UINT8:       return &(entry.as_uint8);
        case PIPE::TYPE::C_STR:       return &(entry.as_char);
        case PIPE::TYPE::UINT64:      return &(entry.as_uint64);
        case PIPE::TYPE::KEY:         return &(entry.as_key);
        case PIPE::TYPE::NONE:        break;
    }

    die();
}

inline void *DATABUS::to_ptr(PIPE &pipe, size_t index) const noexcept {
    switch (pipe.type) {
        case PIPE::TYPE::PTR:
        case PIPE::TYPE::MEMORY_PTR:
        case PIPE::TYPE::BUS_PTR:     return to_ptr(pipe) + index;
        case PIPE::TYPE::UINT8:       return to_uint8(pipe) + index;
        case PIPE::TYPE::C_STR:       return to_char(pipe) + index;
        case PIPE::TYPE::UINT64:      return to_uint64(pipe) + index;
        case PIPE::TYPE::KEY:         return to_key(pipe) + index;
        case PIPE::TYPE::NONE:        break;
    }

    die();
}

inline const void *DATABUS::to_ptr(
    const PIPE &pipe, size_t index
) const noexcept {
    return to_ptr(const_cast<PIPE&>(pipe), index);
}

inline void DATABUS::set_event(BUS &bus, EVENT event, bool value) noexcept {
    if (value == false) {
        rem_event(bus, event);
        return;
    }

    size_t index = static_cast<size_t>(event);

    if (index >= std::extent<decltype(bus.event_lookup)>::value) {
        return die();
    }

    ssize_t pos = bus.event_lookup[index];

    if (pos >= 0) {
        return; // Already set.
    }

    INDEX::ENTRY entry{
        insert(
            INDEX::TYPE::EVENT_TO_BUS,
            make_key(event), make_pipe_entry(&bus)
        )
    };

    if (entry.valid) {
        if (entry.index > std::numeric_limits<ssize_t>::max()) {
            // the number of buses is limited by the SSIZE_MAX.
            return die();
        }

        bus.event_lookup[index] = static_cast<ssize_t>(entry.index);

        return;
    }

    report(entry.error);
    die();
}

inline void DATABUS::rem_event(BUS &bus, EVENT event) noexcept {
    size_t index = static_cast<size_t>(event);

    if (index >= std::extent<decltype(bus.event_lookup)>::value) {
        return die();
    }

    ssize_t pos = bus.event_lookup[index];

    if (pos < 0) {
        return;
    }

    size_t erased = erase(
        INDEX::TYPE::EVENT_TO_BUS,
        make_key(event), make_pipe_entry(&bus), pos, 1
    );

    if (!erased) {
        return die();
    }

    INDEX::ENTRY entry{
        find(INDEX::TYPE::EVENT_TO_BUS, make_key(event), {}, pos, 1)
    };

    if (entry.valid && entry.index == static_cast<size_t>(pos)) {
        BUS *other_bus = to_bus(get_value(entry));
        other_bus->event_lookup[index] = pos;
    }

    bus.event_lookup[index] = -1;
}

inline bool DATABUS::has_event(const BUS &bus, EVENT event) const noexcept {
    size_t index = static_cast<size_t>(event);

    if (index >= std::extent<decltype(bus.event_lookup)>::value) {
        return false;
    }

    return bus.event_lookup[index] >= 0;
}

inline DATABUS::INDEX::ENTRY DATABUS::find(
    INDEX::TYPE index_type, KEY key, PIPE::ENTRY value,
    size_t start_i, size_t iterations
) const noexcept {
    const INDEX &index = indices[size_t(index_type)];

    if (index.buckets <= 0) die();

    INDEX::TABLE &table = index.table[key.value % index.buckets];
    PIPE &key_pipe = table.key;

    if (key_pipe.type != PIPE::TYPE::KEY) {
        die();
    }

    const KEY *const data = to_key(key_pipe);

    if (!data) {
        return {};
    }

    PIPE &val_pipe = table.value;

    if (value.type != PIPE::TYPE::NONE && value.type != val_pipe.type) {
        die();
    }

    size_t sz = key_pipe.size;
    size_t i = std::min(sz-1, start_i);

    for (; i<sz && iterations; --i, --iterations) {
        if (data[i].value != key.value) {
            continue;
        }

        if (value.type != PIPE::TYPE::NONE
        && std::memcmp(to_ptr(val_pipe, i), to_ptr(value), size(value.type))) {
            continue;
        }

        INDEX::ENTRY entry{};

        entry.index = i;
        entry.valid = true;
        entry.key_pipe = &key_pipe;
        entry.val_pipe = &val_pipe;

        return entry;
    }

    return {};
}

inline DATABUS::ERROR DATABUS::reserve(
    INDEX::TYPE index_type, KEY key, size_t capacity
) noexcept {
    ERROR error = ERROR::NONE;
    const INDEX &index = indices[size_t(index_type)];

    if (index.buckets > 0) {
        INDEX::TABLE &table = index.table[key.value % index.buckets];

        error = reserve(table.key, capacity);

        if (!error) {
            error = reserve(table.value, capacity);
        }

        return error;
    }

    die();
}

inline DATABUS::INDEX::ENTRY DATABUS::insert(
    INDEX::TYPE index_type, KEY key, PIPE::ENTRY value
) noexcept {
    INDEX &index = indices[size_t(index_type)];

    if (!index.multimap) {
        INDEX::ENTRY found{ find(index_type, key) };

        if (found.valid) {
            return make_index_entry(
                *found.key_pipe, *found.val_pipe, found.index,
                insert(*found.val_pipe, found.index, value)
            );
        }
    }

    if (index.buckets <= 0) die();

    INDEX::TABLE &table = index.table[key.value % index.buckets];
    PIPE &key_pipe = table.key;

    if (key_pipe.type != PIPE::TYPE::KEY) die();

    PIPE &val_pipe = table.value;

    size_t old_size = key_pipe.size;

    ERROR error{insert(key_pipe, make_pipe_entry(key))};

    if (error == ERROR::NONE) {
        error = insert(val_pipe, value);

        if (error == ERROR::NONE) {
            if (++index.entries > index.buckets && index.autogrow) {
                bitset.reindex = true;
            }
        }
        else {
            if (key_pipe.size > old_size) {
                --key_pipe.size;
            }
            else die();
        }
    }

    return make_index_entry(key_pipe, val_pipe, old_size, error);
}

inline size_t DATABUS::erase(
    INDEX::TYPE index_type, KEY key, PIPE::ENTRY value,
    size_t start_i, size_t iterations
) noexcept {
    INDEX &index = indices[size_t(index_type)];

    if (index.buckets <= 0) die();

    INDEX::TABLE &table = index.table[key.value % index.buckets];
    PIPE &key_pipe = table.key;

    if (key_pipe.type != PIPE::TYPE::KEY) die();

    KEY *const key_data = to_key(key_pipe);

    size_t erased = 0;

    if (!key_data) {
        return erased;
    }

    PIPE &val_pipe = table.value;

    if (value.type != PIPE::TYPE::NONE && value.type != val_pipe.type) {
        die();
    }

    size_t i{
        // We start from the end because erasing the last element is fast.

        std::min(
            key_pipe.size - 1, start_i
        )
    };

    for (; i < key_pipe.size && iterations; --iterations) {
        if (key_data[i].value != key.value) {
            --i;
            continue;
        }

        if (value.type != PIPE::TYPE::NONE
        && std::memcmp(to_ptr(val_pipe, i), to_ptr(value), size(value.type))) {
            i = index.multimap ? i-1 : key_pipe.size;
            continue;
        }

        erase(key_pipe, i);
        erase(val_pipe, i);

        ++erased;

        if (index.multimap) {
            if (i == key_pipe.size) --i;

            continue;
        }

        break;
    }

    index.entries -= erased;

    return erased;
}

inline size_t DATABUS::count(INDEX::TYPE index_type, KEY key) const noexcept {
    size_t count = 0;
    const INDEX &index = indices[size_t(index_type)];

    if (index.buckets > 0) {
        const INDEX::TABLE &table = index.table[key.value % index.buckets];
        const PIPE &pipe = table.key;
        const KEY *const data = to_key(pipe);

        if (data) {
            for (size_t i=0, sz=pipe.size; i<sz; ++i) {
                if (data[i].value == key.value) {
                    ++count;

                    if (!index.multimap) return count;
                }
            }
        }

        return count;
    }

    die();
}

inline DATABUS::ERROR DATABUS::reindex() noexcept {
    for (INDEX &index : indices) {
        if (!index.autogrow || index.entries <= index.buckets) {
            continue;
        }

        const size_t new_buckets = next_pow2(index.entries);

        INDEX::TABLE *new_table = allocate_tables(new_buckets);
        INDEX::TABLE *old_table = index.table;

        if (new_table) {
            for (size_t i=0; i<new_buckets; ++i) {
                new_table[i].key.type = old_table->key.type;
                new_table[i].value.type = old_table->value.type;
            }
        }
        else {
            return ERROR::OUT_OF_MEMORY;
        }

        const size_t old_buckets = index.buckets;
        const size_t old_entries = index.entries;

        index.table = new_table;
        index.buckets = new_buckets;
        index.entries = 0;

        for (size_t i=0; i<old_buckets; ++i) {
            INDEX::TABLE &table = old_table[i];

            for (size_t j=0, sz=table.value.size; j<sz; ++j) {
                INDEX::ENTRY entry{
                    insert(
                        index.type,
                        to_key(get_entry(table.key, j)),
                        get_entry(table.value, j)
                    )
                };

                if (!entry.valid) {
                    index.table = old_table;
                    index.buckets = old_buckets;
                    index.entries = old_entries;

                    destroy_and_delete(new_table, new_buckets);

                    return entry.error;
                }
            }
        }

        destroy_and_delete(old_table, old_buckets);

        if (index.entries != old_entries) {
            report_bug();
        }
    }

    bitset.reindex = false;

    return ERROR::NONE;
}

inline void DATABUS::replace(
    PIPE &pipe, size_t index, PIPE::ENTRY value
) const noexcept {
    if (index >= pipe.size) {
        die();
    }
    else if (pipe.type != value.type) {
        die();
    }

    std::memcpy(to_ptr(pipe, index), to_ptr(value), size(value.type));
}

inline DATABUS::ERROR DATABUS::insert(
    PIPE &pipe, size_t index, PIPE::ENTRY value
) noexcept {
    if (index > pipe.size) {
        die();
    }
    else if (pipe.type != value.type) {
        die();
    }
    else if (index == pipe.size) {
        if (pipe.size == pipe.capacity) {
            ERROR error = reserve(pipe, std::max(pipe.size * 2, size_t{1}));

            if (error != ERROR::NONE) {
                return error;
            }
        }

        ++pipe.size;

        if (pipe.type == PIPE::TYPE::C_STR) {
            ERROR error = null_terminate(pipe);

            if (error != ERROR::NONE) {
                --pipe.size;
                return error;
            }
        }
    }

    replace(pipe, index, value);

    return ERROR::NONE;
}

inline DATABUS::ERROR DATABUS::insert(PIPE &pipe, PIPE::ENTRY value) noexcept {
    return insert(pipe, pipe.size, value);
}

inline DATABUS::ERROR DATABUS::reserve(PIPE &pipe, size_t capacity) noexcept {
    if (pipe.capacity >= capacity) {
        return ERROR::NONE;
    }

    size_t element_size = size(pipe.type);
    size_t byte_count = element_size * capacity;

    if (!byte_count) {
        die();
    }

    MEMORY *const old_memory = pipe.memory;

    if (old_memory && old_memory->size / element_size >= capacity) {
        pipe.capacity = capacity;

        return ERROR::NONE;
    }

    MEMORY *const new_memory = allocate(byte_count, align(pipe.type));

    if (!new_memory) {
        return ERROR::OUT_OF_MEMORY;
    }

    void *const old_data = pipe.data;
    void *const new_data = new_memory->data;

    if (old_data) {
        std::memcpy(new_data, old_data, pipe.size * element_size);
    }

    if (old_memory) {
        recycle(*old_memory);
    }

    pipe.memory = new_memory;
    pipe.data = new_data;
    pipe.capacity = capacity;

    return ERROR::NONE;
}

inline DATABUS::ERROR DATABUS::copy(const PIPE &src, PIPE &dst) noexcept {
    if (&src == &dst) {
        return ERROR::NONE;
    }

    if (src.type != dst.type || dst.type == PIPE::TYPE::NONE) {
        die();
    }

    dst.size = 0;

    return append(src, dst);
}

inline DATABUS::ERROR DATABUS::append(const PIPE &src, PIPE &dst) noexcept {
    if (src.type != dst.type
    ||  dst.type == PIPE::TYPE::NONE) {
        die();
    }

    size_t padding{ dst.type == PIPE::TYPE::C_STR ? size_t{1} : size_t{0} };
    size_t old_size = dst.size;
    size_t new_size = old_size + src.size;

    if (new_size + padding > dst.capacity) {
        ERROR error = reserve(dst, new_size + padding);

        if (error != ERROR::NONE) {
            return error;
        }
    }

    size_t count = src.size;

    dst.size = new_size;

    if (src.data == nullptr) {
        return ERROR::NONE;
    }
    else if (src.data == dst.data) die();

    if (padding && null_terminate(dst) != ERROR::NONE) {
        die(); // This should never happen because we reserved extra space.
    }

    std::memcpy(to_ptr(dst, old_size), to_ptr(src, 0), count * size(dst.type));

    return ERROR::NONE;
}

inline DATABUS::ERROR DATABUS::null_terminate(PIPE &pipe) noexcept {
    if (pipe.size >= pipe.capacity) {
        ERROR error = reserve(pipe, pipe.size + 1);

        if (error != ERROR::NONE) {
            return error;
        }
    }

    const_cast<const DATABUS&>(*this).null_terminate(pipe);

    return ERROR::NONE;
}

inline void DATABUS::null_terminate(PIPE &pipe) const noexcept {
    if (pipe.size >= pipe.capacity) {
        die();
    }

    replace(pipe, pipe.size++, make_pipe_entry(pipe.type));
    --pipe.size;
}

inline void DATABUS::erase(PIPE &pipe, size_t index) const noexcept {
    if (index >= pipe.size) {
        die();
    }

    if (index + 1 < pipe.size) {
        std::memcpy(
            to_ptr(pipe, index), to_ptr(pipe, pipe.size - 1), size(pipe.type)
        );
    }

    --pipe.size;

    if (pipe.type == PIPE::TYPE::C_STR) {
        null_terminate(pipe);
    }
}

inline DATABUS::PIPE::ENTRY DATABUS::pop_back(PIPE &pipe) const noexcept {
    size_t size = pipe.size;

    if (size) {
        PIPE::ENTRY entry{get_last(pipe)};

        erase(pipe, size - 1);

        return entry;
    }

    die();
}

inline DATABUS::PIPE::ENTRY DATABUS::get_last(const PIPE &pipe) const noexcept {
    size_t size = pipe.size;

    if (size) {
        return get_entry(pipe, size - 1);
    }

    die();
}

inline DATABUS::PIPE::ENTRY DATABUS::get_entry(
    const PIPE &pipe, size_t index
) const noexcept {
    if (index < pipe.size) {
        PIPE::ENTRY entry{};

        entry.type = pipe.type;

        std::memcpy(to_ptr(entry), to_ptr(pipe, index), size(entry.type));

        return entry;
    }

    die();
}

inline void DATABUS::set_value(
    INDEX::ENTRY index_entry, PIPE::ENTRY pipe_entry
) noexcept {
    replace(*index_entry.val_pipe, index_entry.index, pipe_entry);
}

inline DATABUS::PIPE::ENTRY DATABUS::get_value(
    INDEX::ENTRY entry
) const noexcept {
    return get_entry(*entry.val_pipe, entry.index);
}

inline void DATABUS::destroy(PIPE &pipe) noexcept {
    if (pipe.memory) {
        recycle(*pipe.memory);
        pipe.memory = nullptr;
    }

    pipe.data = nullptr;
    pipe.capacity = 0;
    pipe.size = 0;
}

inline void DATABUS::enlist(MEMORY &memory, MEMORY *&list) noexcept {
    if (memory.next || memory.prev) die();

    memory.next = list;

    if (list) {
        list->prev = &memory;
    }

    list = &memory;
}

inline void DATABUS::unlist(MEMORY &memory, MEMORY *&list) noexcept {
    if (memory.indexed) {
        const KEY key{make_key(reinterpret_cast<uintptr_t>(memory.data))};
        INDEX::ENTRY entry{ find(INDEX::TYPE::RESOURCE_TO_MEMORY, key) };

        size_t erased{
            entry.valid ? (
                erase(INDEX::TYPE::RESOURCE_TO_MEMORY, key, {}, entry.index, 1)
            ) : 0
        };

        if (!erased) {
            return die();
        }

        memory.indexed = false;
    }

    if (list == &memory) {
        list = memory.next;

        if (list) {
            list->prev = nullptr;
        }
    }
    else {
        memory.prev->next = memory.next;

        if (memory.next) {
            memory.next->prev = memory.prev;
        }
    }

    memory.next = nullptr;
    memory.prev = nullptr;
}

inline const DATABUS::MEMORY *DATABUS::find_memory(
    const void *resource
) const noexcept {
    INDEX::ENTRY entry{
        find(
            INDEX::TYPE::RESOURCE_TO_MEMORY,
            make_key(reinterpret_cast<uintptr_t>(resource))
        )
    };

    if (entry.valid) {
        return to_memory(get_value(entry));
    }

    die();
}

inline DATABUS::MEMORY *DATABUS::find_memory(const void *resource) noexcept {
    return const_cast<MEMORY *>(
        static_cast<const DATABUS &>(*this).find_memory(resource)
    );
}

inline const DATABUS::MEMORY &DATABUS::get_memory(
    const void *resource
) const noexcept {
    const MEMORY *const memory = find_memory(resource);

    if (memory) {
        return *memory;
    }

    die();
}

inline DATABUS::MEMORY &DATABUS::get_memory(const void *resource) noexcept {
    MEMORY *const memory = find_memory(resource);

    if (memory) {
        return *memory;
    }

    die();
}

inline DATABUS::INDEX::TABLE *DATABUS::allocate_tables(size_t count) noexcept {
    const size_t total_size = sizeof(INDEX::TABLE) * count;
    const auto usage_left{
        std::numeric_limits<decltype(mempool.usage)>::max() - mempool.usage
    };

    INDEX::TABLE *tables = (
        usage_left >= total_size &&
        mempool.cap >= mempool.usage + total_size ? (
            new (std::nothrow) INDEX::TABLE [count]()
        ) : nullptr
    );

    if (!tables) {
        return nullptr;
    }

    mempool.usage += total_size;

    return tables;
}

inline void DATABUS::destroy_and_delete(
    INDEX::TABLE *tables, size_t count
) noexcept {
    for (size_t i=0; i<count; ++i) {
        destroy(tables[i].key);
        destroy(tables[i].value);
    }

    delete [] tables;

    mempool.usage -= sizeof(INDEX::TABLE) * count;
}

inline DATABUS::MEMORY *DATABUS::allocate(
    const size_t requested_byte_count, size_t align
) noexcept {
    align = std::max(alignof(MEMORY), align);
    size_t byte_count = next_pow2(requested_byte_count); // Always at least 1.
    const size_t padding = (align - sizeof(MEMORY) % align) % align;
    const size_t total_size = sizeof(MEMORY) + padding + byte_count;
    MEMORY *memory = nullptr;

    do {
        MEMORY *&free = mempool.free[clz(byte_count)];

        if (!free) {
            break;
        }

        for (MEMORY *m = free; m != nullptr; m = m->next) {
            const size_t old_padding{
                reinterpret_cast<uintptr_t>(m->data) -
                reinterpret_cast<uintptr_t>(m) - sizeof(MEMORY)
            };

            if (padding > old_padding) {
                const size_t deficit = padding - old_padding;

                if (m->size < requested_byte_count + deficit) {
                    continue;
                }

                m->size -= deficit;
            }
            else {
                m->size += old_padding - padding;
            }

            m->data = reinterpret_cast<void *>(
                reinterpret_cast<uintptr_t>(m) + sizeof(MEMORY) + padding
            );

            unlist(*m, free);
            memory = m;

            break;
        }
    }
    while (false);

    if (!memory) {
        const auto usage_left{
            std::numeric_limits<decltype(mempool.usage)>::max() - mempool.usage
        };

        for (size_t i=0; i<2; ++i) {
            memory = static_cast<MEMORY *>(
                usage_left >= total_size &&
                mempool.cap >= mempool.usage + total_size ? (
                    std::aligned_alloc(align, total_size)
                ) : nullptr
            );

            if (!memory) {
                for (MEMORY *&free : mempool.free) {
                    while (free) {
                        deallocate(*free);
                    }
                }
            }
        }

        if (!memory) {
            mempool.oom = true;
            return nullptr;
        }

        if (reinterpret_cast<std::uintptr_t>(memory) % alignof(MEMORY)) {
            if (fuse()) report_bug("misaligned pointer detected");
        }

        mempool.usage += total_size;

        memory->size = byte_count;
        memory->data = reinterpret_cast<void *>(
            reinterpret_cast<uintptr_t>(memory) + sizeof(MEMORY) + padding
        );
    }

    memory->next = nullptr;
    memory->prev = nullptr;
    memory->indexed = false;
    memory->recycled = false;

    enlist(*memory, mempool.list);

    if (reinterpret_cast<std::uintptr_t>(memory->data) % align) {
        if (fuse()) report_bug("misaligned pointer detected");
    }

    return memory;
}

inline DATABUS::MEMORY *DATABUS::allocate_and_index(
    size_t byte_count, size_t alignment, const void *copy
) noexcept {
    MEMORY *memory = allocate(byte_count, alignment);

    if (!memory) {
        return nullptr;
    }

    if (copy) {
        std::memcpy(memory->data, copy, memory->size);
    }

    INDEX::ENTRY entry{
        insert(
            INDEX::TYPE::RESOURCE_TO_MEMORY,
            make_key(reinterpret_cast<uintptr_t>(memory->data)),
            make_pipe_entry(memory)
        )
    };

    if (entry.valid) {
        memory->indexed = true;
    }
    else {
        recycle(*memory);
        return nullptr;
    }

    return memory;
}

inline void DATABUS::deallocate(MEMORY &memory) noexcept {
    if (memory.recycled) {
        MEMORY *&free = mempool.free[clz(memory.size)];
        unlist(memory, free);
    }
    else {
        unlist(memory, mempool.list);
    }

    const size_t total_size{
        reinterpret_cast<uintptr_t>(memory.data) -
        reinterpret_cast<uintptr_t>(&memory) + memory.size
    };

    std::free(&memory);

    if (total_size <= mempool.usage) {
        mempool.usage -= total_size;
    }
    else {
        if (fuse()) report_bug("detected memory usage tracking corruption");

        mempool.usage = 0;
    }
}

inline void DATABUS::recycle(MEMORY &memory) noexcept {
    if (memory.recycled) {
        return;
    }

    unlist(memory, mempool.list);
    enlist(memory, mempool.free[clz(memory.size)]);

    memory.recycled = true;
}

inline DATABUS::BUS *DATABUS::new_bus(const BUS &copy) noexcept {
    MEMORY *const mem = allocate_and_index(sizeof(BUS), alignof(BUS), &copy);

    return mem ? reinterpret_cast<BUS *>(mem->data) : nullptr;
}

inline DATABUS::RESULT DATABUS::call_sigfillset(
    sigset_t *set, const char *file, int line
) noexcept {
    int errno_orig = errno;
    errno = 0;

    ERROR error = ERROR::NONE;
    const char *str = "";
    int retval = sigfillset(set), code = errno;

    if (retval == -1) {
        str = strerror(code);

        switch (code) {
            case EINVAL: //____________________________________ Invalid argument
            {
                error = ERROR::LIBRARY;
                break;
            }
            default:
            {
                error = ERROR::SYSTEM;
                break;
            }
        }
    }
    else {
        code = 0;

        if (retval) {
            error = ERROR::UNKNOWN;
            str = "unexpected return value";
        }
    }

    errno = errno_orig;

    return make_result(
        retval, code, error, str, TAIL(__FUNCTION__, '_'), file, line
    );
}

inline DATABUS::RESULT DATABUS::call_sigemptyset(
    sigset_t *set, const char *file, int line
) noexcept {
    int errno_orig = errno;
    errno = 0;

    ERROR error = ERROR::NONE;
    const char *str = "";
    int retval = sigemptyset(set), code = errno;

    if (retval == -1) {
        str = strerror(code);

        switch (code) {
            case EINVAL: //____________________________________ Invalid argument
            {
                error = ERROR::LIBRARY;
                break;
            }
            default:
            {
                error = ERROR::SYSTEM;
                break;
            }
        }
    }
    else {
        code = 0;

        if (retval) {
            error = ERROR::UNKNOWN;
            str = "unexpected return value";
        }
    }

    errno = errno_orig;

    return make_result(
        retval, code, error, str, TAIL(__FUNCTION__, '_'), file, line
    );
}

inline DATABUS::RESULT DATABUS::call_pthread_sigmask(
    int how, const sigset_t *set, sigset_t *oldset, const char *file, int line
) const noexcept {
    int errno_orig = errno;
    errno = 0;

    ERROR error = ERROR::NONE;
    const char *str = "";
    int retval = pthread_sigmask(how, set, oldset), code = errno;

    if (retval == -1) {
        str = strerror(code);

        switch (code) {
            case EFAULT: //_________________________________________ Bad address
            case EINVAL: //____________________________________ Invalid argument
            {
                error = ERROR::LIBRARY;
                break;
            }
            default:
            {
                error = ERROR::SYSTEM;
                break;
            }
        }
    }
    else {
        code = 0;

        if (retval) {
            error = ERROR::UNKNOWN;
            str = "unexpected return value";
        }
    }

    errno = errno_orig;

    return make_result(
        retval, code, error, str, TAIL(__FUNCTION__, '_'), file, line
    );
}

constexpr DATABUS::KEY DATABUS::make_key(uintptr_t val) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::KEY{
        .value = val
    };
}

constexpr DATABUS::KEY DATABUS::make_key(EVENT val) noexcept {
    return make_key(static_cast<uintptr_t>(val));
}

constexpr DATABUS::RESULT DATABUS::make_result(
    int value, int code, ERROR error,
    const char *text, const char *call, const char *file, int line
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    RESULT{
        .value = value,
        .code  = code,
        .text  = text,
        .call  = call,
        .file  = file,
        .line  = line,
        .error = error
    };
}

constexpr DATABUS::BUS DATABUS::make_bus(size_t id, PIPE payload) noexcept {
#if __cplusplus <= 201703L
    __extension__
#endif
    BUS bus{
        .id{id},
        .event_lookup{},
        .payload{payload}
    };

    for (auto &lookup_value : bus.event_lookup) {
        lookup_value = -1;
    }

    return bus;
}

constexpr DATABUS::MEMPOOL DATABUS::make_mempool() noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::MEMPOOL{
        .free  = {},
        .list  = nullptr,
        .usage = 0,
        .top   = 0,
        .cap   = std::numeric_limits<decltype(MEMPOOL::cap)>::max(),
        .oom   = false
    };
}

constexpr DATABUS::ALERT DATABUS::make_alert(
    size_t bus, EVENT event, bool valid
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    ALERT{
        .bus   = bus,
        .event = event,
        .valid = valid
    };
}

constexpr DATABUS::ENTRY DATABUS::make_entry(
    size_t id, size_t size, void *data, ERROR error, bool valid
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    ENTRY{
        .id    = id,
        .size  = size,
        .data  = data,
        .c_str = static_cast<const char*>(data),
        .error = error,
        .valid = valid
    };
}

constexpr DATABUS::ENTRY DATABUS::make_entry(ERROR error) noexcept {
    return make_entry(0, 0, nullptr, error, false);
}

constexpr struct DATABUS::INDEX::ENTRY DATABUS::make_index_entry(
    PIPE &keys, PIPE &values, size_t index, ERROR error, bool valid
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::INDEX::ENTRY{
        .key_pipe = &keys,
        .val_pipe = &values,
        .index    = index,
        .error    = error,
        .valid    = valid
    };
}

constexpr struct DATABUS::INDEX::ENTRY DATABUS::make_index_entry(
    PIPE &keys, PIPE &values, size_t index, ERROR error
) noexcept {
    return make_index_entry(keys, values, index, error, error == ERROR::NONE);
}

constexpr DATABUS::PIPE DATABUS::make_pipe(
    const void *data, size_t size, PIPE::TYPE type
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::PIPE{
        .capacity = size,
        .size = size,
        .data = const_cast<void *>(data),
        .type = type,
        .memory = nullptr
    };
}

constexpr DATABUS::PIPE DATABUS::make_pipe(PIPE::TYPE type) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::PIPE{
        .capacity = 0,
        .size = 0,
        .data = nullptr,
        .type = type,
        .memory = nullptr
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    PIPE::TYPE type
) noexcept {
    PIPE::ENTRY entry{};
    entry.type = type;
    return entry;
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    uint64_t value
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::PIPE::ENTRY{
        .as_uint64 = value,
        .type = PIPE::TYPE::UINT64
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    KEY value
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::PIPE::ENTRY{
        .as_key = value,
        .type = PIPE::TYPE::KEY
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    BUS *value
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::PIPE::ENTRY{
        .as_ptr = value,
        .type = PIPE::TYPE::BUS_PTR
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    MEMORY *value
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    DATABUS::PIPE::ENTRY{
        .as_ptr = value,
        .type = PIPE::TYPE::MEMORY_PTR
    };
}

constexpr struct DATABUS::QUERY DATABUS::make_query_by_event(
    EVENT event
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    QUERY{
        .bus_event = event,
        .type = QUERY::TYPE::BUS_BY_EVENT
    };
}

constexpr struct DATABUS::QUERY DATABUS::make_query_by_id(
    size_t bus_id
) noexcept {
    return
#if __cplusplus <= 201703L
    __extension__
#endif
    QUERY{
        .bus_id = bus_id,
        .type = QUERY::TYPE::BUS_BY_ID
    };
}

constexpr const char *DATABUS::to_string(ERROR error) noexcept {
    switch (error) {
        case ERROR::NONE:          return "no error";
        case ERROR::LIBRARY:       return "library error";
        case ERROR::BAD_REQUEST:   return "invalid request";
        case ERROR::SYSTEM:        return "system error";
        case ERROR::PENDING_ALERT: return "unhandled events";
        case ERROR::OUT_OF_MEMORY: return "out of memory";
        case ERROR::UNKNOWN:       return "unknown error";
    }

    return "undefined error";
}

constexpr DATABUS::EVENT DATABUS::next(EVENT event_type) noexcept {
    return static_cast<EVENT>(
        (static_cast<size_t>(event_type) + 1) % (
            static_cast<size_t>(EVENT::MAX_EVENTS)
        )
    );
}

constexpr size_t DATABUS::size(PIPE::TYPE type) noexcept {
    switch (type) {
        case PIPE::TYPE::UINT8:       return sizeof(uint8_t);
        case PIPE::TYPE::C_STR:       return sizeof(char);
        case PIPE::TYPE::UINT64:      return sizeof(uint64_t);
        case PIPE::TYPE::PTR:         return sizeof(void *);
        case PIPE::TYPE::BUS_PTR:     return sizeof(BUS *);
        case PIPE::TYPE::MEMORY_PTR:  return sizeof(MEMORY *);
        case PIPE::TYPE::KEY:         return sizeof(KEY);
        case PIPE::TYPE::NONE:        break;
    }

    return 0;
}

constexpr size_t DATABUS::align(PIPE::TYPE type) noexcept {
    switch (type) {
        case PIPE::TYPE::UINT8:       return alignof(uint8_t);
        case PIPE::TYPE::C_STR:       return alignof(char);
        case PIPE::TYPE::UINT64:      return alignof(uint64_t);
        case PIPE::TYPE::PTR:         return alignof(void *);
        case PIPE::TYPE::BUS_PTR:     return alignof(BUS *);
        case PIPE::TYPE::MEMORY_PTR:  return alignof(MEMORY *);
        case PIPE::TYPE::KEY:         return alignof(KEY);
        case PIPE::TYPE::NONE:        break;
    }

    return 0;
}

constexpr const char *DATABUS::LEAF(const char* path) noexcept {
    const char* file = path;

    while (*path) {
        if (*path++ == '/') {
            file = path;
        }
    }

    return file;
}

constexpr const char *DATABUS::TAIL(const char* snake, char neck) noexcept {
    const char* tail = snake;

    while (*snake) {
        if (*snake++ == neck) {
            tail = snake;
            break;
        }
    }

    return tail;
}

inline int DATABUS::clz(unsigned int x) noexcept {
    return __builtin_clz(x);
}

inline int DATABUS::clz(unsigned long x) noexcept {
    return __builtin_clzl(x);
}

inline int DATABUS::clz(unsigned long long x) noexcept {
    return __builtin_clzll(x);
}

inline unsigned int DATABUS::next_pow2(unsigned int x) noexcept {
    return x <= 1 ? 1 : 1 << ((sizeof(x) * BITS_PER_BYTE) - clz(x - 1));
}

inline unsigned long DATABUS::next_pow2(unsigned long x) noexcept {
    return x <= 1 ? 1 : 1 << ((sizeof(x) * BITS_PER_BYTE) - clz(x - 1));
}

inline unsigned long long DATABUS::next_pow2(unsigned long long x) noexcept {
    return x <= 1 ? 1 : 1 << ((sizeof(x) * BITS_PER_BYTE) - clz(x - 1));
}

static_assert(
    __LINE__ < sizeof(DATABUS::fuses) * DATABUS::BITS_PER_BYTE,
    "number of fuse bits should exceed the line count of this file"
);

#endif
