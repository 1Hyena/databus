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

#include <bit>
#include <algorithm>
#include <limits>
#include <array>
#include <numeric>

#include <csignal>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <cstdio>

class DATABUS final {
    public:
    static constexpr const char *const VERSION = "0.01";

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
        FINALIZE,
        // Do not change the list below this line.
        MAX_EVENTS
    };

    static constexpr const EVENT
        NO_EVENT    = EVENT::NONE,
        SYNCHRONIZE = EVENT::SYNCHRONIZE,
        DESERIALIZE = EVENT::DESERIALIZE,
        SERIALIZE   = EVENT::SERIALIZE,
        FINALIZE    = EVENT::FINALIZE;

    static constexpr const char *to_string(EVENT) noexcept;

    struct ALERT {
        size_t entry;
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
    bool idle() const noexcept;

    void set_logger(void (*callback)(ERROR, const char *) noexcept) noexcept;
    void set_logger(
        void (*callback)(ERROR, const char *, void *) noexcept, void *userdata
    ) noexcept;
    void set_memcap(size_t bytes) noexcept;
    void set_matrix(
        size_t id, size_t size,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    void set_random(uint64_t) noexcept;
    size_t get_memcap() const noexcept;
    size_t get_memtop() const noexcept;
    size_t get_id() const noexcept;
    uint64_t next_random() noexcept;

    ERROR next_error() noexcept;
    ERROR last_error() noexcept;
    ALERT next_alert() noexcept;
    void  kick_start() noexcept;

    size_t peek(const void **buf =nullptr) const noexcept;
    size_t read(void *buf, size_t count) noexcept;
    [[nodiscard]] ERROR write(const void *buf, size_t count) noexcept;
    size_t reserve(size_t size) noexcept;
    size_t capacity() noexcept;

    ERROR set_entry(
        size_t id, const void *data, size_t size,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    ERROR set_entry(
        size_t id, const char *c_str,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    ENTRY get_entry(size_t id) const noexcept;
    ERROR set_container(
        size_t id, size_t container_id,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    size_t get_container(
        size_t id,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;
    size_t get_content(
        size_t id, size_t index,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) const noexcept;

    static constexpr const size_t BITS_PER_BYTE{
        std::numeric_limits<unsigned char>::digits
    };

    static uint16_t crc16(uint16_t crc, const void *data, size_t size) noexcept;

    private:
    struct PACKET {
        enum class TYPE : uint8_t {
            NONE = 0,
            ENTRY,
            ETB // End-of-Transmission-Block
        };

        size_t size;
        void  *data;
        TYPE   type;
    };

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
            FLAG_TO_BUS,
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

    struct MACHINE {
        enum class STATE : uint8_t {
            NONE = 0,
            SERIALIZING,
            TRANSMITTING,
            SYNCHRONIZING,
            DESERIALIZING,
            FINALIZING
        };

        size_t   nodes;
        size_t   peers;
        size_t   buses;
        size_t   etb;
        uint16_t id;
        STATE    state;
    };

    struct BUS {
        enum class FLAG : unsigned char {
            NONE = 0,
            // Do not change the list above this line.
            RECEIVE,
            UPDATING,
            UPDATE,
            TRANSMIT,
            TRANSMITTING,
            BLOCKED,
            REBLOCK,
            RECYCLE,
            // Do not change the list below this line.
            MAX_FLAGS
        };

        size_t id;
        ssize_t flag_lookup[ static_cast<size_t>(FLAG::MAX_FLAGS) ];
        PIPE payload;

        struct RANK {
            size_t index;

            struct {
                struct {
                    size_t id;
                } bus;
            } master;

            struct {
                size_t serialized;
                PIPE list;
            } slaves;
        } rank;

        struct {
            decltype(MACHINE::id) id;
        } machine;

        struct {
            struct {
                decltype(MACHINE::id) id;
            } machine;
        } next;

        struct BITSET {
            bool serialized:1;
            bool changed:1;
        } bitset;
    };

    static constexpr const char *to_string(BUS::FLAG) noexcept;

    struct QUERY {
        enum class TYPE : uint8_t {
            BUS_BY_ID,
            BUS_BY_FLAG
        };

        union {
            size_t    bus_id;
            BUS::FLAG bus_flag;
        };
        TYPE type;
    };

    static constexpr MACHINE make_machine() noexcept;
    static constexpr KEY make_key(uintptr_t) noexcept;
    static constexpr KEY make_key(BUS::FLAG) noexcept;
    static constexpr struct BUS make_bus(
        size_t id, PIPE pipe =make_pipe(PIPE::TYPE::C_STR)
    ) noexcept;
    static constexpr struct BUS::RANK make_bus_rank() noexcept;

    static constexpr struct ALERT make_alert(
        size_t entry, EVENT type, bool valid =true
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
    static constexpr QUERY make_query_by_flag(BUS::FLAG) noexcept;

    static constexpr uint64_t nbo64(uint64_t) noexcept;
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
    static size_t encode(
        uint64_t, void * =nullptr, size_t =std::numeric_limits<size_t>::max()
    ) noexcept;
    static size_t encode(uint64_t, std::array<uint8_t, 10> &) noexcept;
    static size_t decode(const void *, size_t, uint64_t *) noexcept;
    static uint64_t to_uint64(BUS::BITSET) noexcept;
    static BUS::BITSET to_bus_bitset(uint64_t) noexcept;

    ERROR create_entry(size_t id, const void *data, size_t size) noexcept;
    ERROR update_entry(size_t id, const void *data, size_t size) noexcept;
    ERROR delete_entry(size_t id) noexcept;
    [[nodiscard]] ERROR capture(const BUS &copy) noexcept;
    void release(BUS *) noexcept;

    BUS *find_bus(const QUERY &) const noexcept;
    BUS &get_bus(const QUERY &) const noexcept;
    const PIPE *find_buses(BUS::FLAG) const noexcept;
    BUS *find_master(const BUS &, BUS::FLAG) const noexcept;
    BUS *find_master(const BUS &) const noexcept;

    void set_flag(
        BUS &, BUS::FLAG, bool val =true,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    void rem_flag(
        BUS &, BUS::FLAG,
        const char *file =LEAF(__builtin_FILE()), int line =__builtin_LINE()
    ) noexcept;
    [[nodiscard]] bool has_flag(const BUS &, BUS::FLAG) const noexcept;
    [[nodiscard]] decltype(MACHINE::id) domain(const BUS &) const noexcept;
    [[nodiscard]] ERROR transfer(BUS &, BUS *) noexcept;

    ERROR transmit(
        std::initializer_list<uint64_t> headers,
        const void *data =nullptr, size_t size =0
    ) noexcept;
    ERROR transmit(const BUS &) noexcept;
    ERROR transmit_etb() noexcept;
    ERROR receive() noexcept;
    ERROR receive_entry(const uint8_t *data, size_t len) noexcept;
    ERROR receive_etb(const uint8_t *data, size_t len) noexcept;

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
    [[nodiscard]] ERROR append(PIPE &dst, const PIPE &src) noexcept;
    [[nodiscard]] ERROR append(PIPE &dst, const uint8_t*, size_t) noexcept;
    [[nodiscard]] ERROR null_terminate(PIPE &) noexcept;
    void null_terminate(PIPE &) const noexcept;
    void replace(PIPE&, size_t index, PIPE::ENTRY) const noexcept;
    INDEX &get_index(INDEX::TYPE) noexcept;

    KEY       to_key   (PIPE::ENTRY) const noexcept;
    BUS      *to_bus   (PIPE::ENTRY) const noexcept;
    MEMORY   *to_memory(PIPE::ENTRY) const noexcept;
    int       to_int   (PIPE::ENTRY) const noexcept;
    uint64_t  to_uint64(PIPE::ENTRY) const noexcept;

    int      *to_int    (const PIPE &) const noexcept;
    char     *to_char   (const PIPE &) const noexcept;
    uint8_t  *to_uint8  (const PIPE &) const noexcept;
    uint64_t *to_uint64 (const PIPE &) const noexcept;
    KEY      *to_key    (const PIPE &) const noexcept;
    void    **to_ptr    (const PIPE &) const noexcept;
    BUS     **to_bus_ptr(const PIPE &) const noexcept;

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
    void (*log_userdata_callback)(ERROR, const char *text, void *) noexcept;
    void *log_userdata;
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

    MACHINE machine;
    PIPE incoming;
    PIPE outgoing;
    ERROR errored;

    struct BITSET {
        bool alerted:1;
        bool waiting:1;
        bool synched:1;
        bool reindex:1;
    } bitset;

    uint64_t random;
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
    log_callback(nullptr), log_userdata_callback(nullptr),
    log_userdata(nullptr), indices{}, mempool{make_mempool()},
    machine{make_machine()}, incoming{}, outgoing{}, errored{},
    bitset{}, random{reinterpret_cast<uintptr_t>(this)},
    sigset_all{}, sigset_none{}, fuses{} {
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

    destroy(outgoing);
    destroy(incoming);

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

    const auto machine_id = machine.id;
    const auto machine_nodes = machine.nodes;
    const auto machine_peers = machine.peers;
    machine = make_machine();
    machine.id = machine_id;
    machine.nodes = machine_nodes;
    machine.peers = machine_peers;

    bitset = {};

    std::fill(fuses, fuses+sizeof(fuses), 0);
}

inline bool DATABUS::init() noexcept {
    if (machine.id == 0 || machine.id > machine.nodes) {
        log("%s: invalid matrix configuration", __FUNCTION__);

        return false;
    }

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
            case INDEX::TYPE::FLAG_TO_BUS: {
                index.buckets = static_cast<size_t>(BUS::FLAG::MAX_FLAGS);
                index.multimap = true;
                index.autogrow = false;
                break;
            }
        }

        switch (index.type) {
            case INDEX::TYPE::NONE: continue;
            case INDEX::TYPE::FLAG_TO_BUS:
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
                case INDEX::TYPE::FLAG_TO_BUS: {
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

    incoming.type = PIPE::TYPE::UINT8;
    outgoing.type = PIPE::TYPE::UINT8;
    machine.state = MACHINE::STATE::SERIALIZING;

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
    log_userdata = nullptr;
    log_userdata_callback = nullptr;
}

inline void DATABUS::set_logger(
    void (*callback)(ERROR, const char *, void *) noexcept, void *userdata
) noexcept {
    log_callback = nullptr;
    log_userdata_callback = callback;
    log_userdata = userdata;
}

inline void DATABUS::set_memcap(size_t bytes) noexcept {
    mempool.cap = bytes;
}

inline void DATABUS::set_matrix(
    size_t id, size_t size, const char *file, int line
) noexcept {
    if (!id || id > size) {
        log("%s: invalid parameters (%s:%d)", __FUNCTION__, file, line);
    }

    if (id > std::numeric_limits<decltype(MACHINE::id)>::max()) {
        log("%s: id too large (%s:%d)", __FUNCTION__, file, line);
    }

    machine.id = static_cast<decltype(MACHINE::id)>(id);
    machine.nodes = size;
    machine.peers = size - 1;
}

inline void DATABUS::set_random(uint64_t seed) noexcept {
    random = seed;
}

inline size_t DATABUS::get_memcap() const noexcept {
    return mempool.cap;
}

inline size_t DATABUS::get_memtop() const noexcept {
    return mempool.top;
}

inline size_t DATABUS::get_id() const noexcept {
    return machine.id;
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

inline DATABUS::ERROR DATABUS::next_error() noexcept {
    if (mempool.usage > mempool.top) {
        mempool.top = mempool.usage;

        log(
            "top memory usage is %.3f %s",
            fmt_bytes(mempool.top).value, fmt_bytes(mempool.top).unit
        );
    }

    Again:

    if (mempool.oom) {
        mempool.oom = false;
        return err(ERROR::OUT_OF_MEMORY);
    }

    switch (machine.state) {
        case MACHINE::STATE::SERIALIZING: {
            if (find_bus(make_query_by_flag(BUS::FLAG::UPDATE))) {
                if (!bitset.alerted) {
                    bitset.alerted = true;

                    return ERROR::NONE;
                }

                return report(
                    ERROR::PENDING_ALERT,
                    "%s", "cannot proceed if there are unhandled events"
                );
            }

            machine.state = MACHINE::STATE::TRANSMITTING;

            [[fallthrough]];
        }
        case MACHINE::STATE::TRANSMITTING: {
            BUS *bus;

            while ((bus = find_bus(make_query_by_flag(BUS::FLAG::TRANSMIT)))) {
                rem_flag(*bus, BUS::FLAG::TRANSMIT);

                if (bus->bitset.changed == false) {
                    BUS *master = find_master(*bus);

                    // If this database entry has not been changed and we can
                    // safely assume that our peers are not waiting for us to
                    // explicitly declare this entry as serialized, then we do
                    // not transmit it. This optimization reduces bandwidth use.

                    if (!master || master->bitset.serialized) {
                        continue;
                    }

                    if (master->machine.id == machine.id) {
                        BUS *grandmaster = find_master(*master);

                        if (!grandmaster
                        || grandmaster->machine.id == machine.id) {
                            continue;
                        }
                    }
                }

                if (bus->rank.master.bus.id) {
                    bool urgent = true;

                    for (BUS *master = find_master(*bus); master;) {
                        if (master->machine.id != machine.id) {
                            break;
                        }

                        if (!master->bitset.serialized) {
                            urgent = false;
                            break;
                        }

                        master = find_master(*master);
                    }

                    if (!urgent) {
                        // Let's postpone this transmission because our bus
                        // could still be changed during the serialization of
                        // some of its masters. This is just an optimization to
                        // reduce the number of transmissions.

                        set_flag(*bus, BUS::FLAG::BLOCKED);

                        continue;
                    }

                    if (find_master(*bus, BUS::FLAG::TRANSMIT)) {
                        // Let's postpone transmission because the given entry
                        // has a master that may also be transmitted. The
                        // transmission of the master has a higher priority.

                        set_flag(*bus, BUS::FLAG::TRANSMITTING);

                        continue;
                    }
                }

                if (!bus->bitset.serialized) {
                    if (domain(*bus) != machine.id) {
                        // How can we have changed it if it's not in our domain?
                        die();
                    }

                    if (bus->machine.id == machine.id) {
                        die(); // We have not serialized it but we should have.
                    }

                    // This bus has not been transmitted eariler most likely
                    // because it didn't change and thus there was no urgent
                    // need to transmit it. However, now it has changed and
                    // therefore we have to mark it as serialized.

                    bus->bitset.serialized = true;
                    set_flag(*bus, BUS::FLAG::RECYCLE);

                    if (bus->rank.master.bus.id) {
                        BUS &master = get_bus(
                            make_query_by_id(bus->rank.master.bus.id)
                        );

                        BUS::RANK &rank = master.rank;

                        if (rank.slaves.serialized >= rank.slaves.list.size) {
                            die();
                        }

                        ++rank.slaves.serialized;
                    }
                }

                const auto prev_next_id = bus->next.machine.id;
                const uint64_t  next_id = 1 + next_random() % machine.nodes;

                bus->next.machine.id = (
                    static_cast<decltype(BUS::next.machine.id)>(next_id)
                );

                ERROR error = transmit(*bus);

                if (!error) {
                    bus->bitset.changed = false;
                }
                else {
                    bus->next.machine.id = prev_next_id;

                    return err(error);
                }
            }

            for (;;) {
                bus = find_bus(make_query_by_flag(BUS::FLAG::TRANSMITTING));

                if (!bus) {
                    break;
                }

                rem_flag(*bus, BUS::FLAG::TRANSMITTING);
                set_flag(*bus, BUS::FLAG::TRANSMIT);
            }

            if (find_bus(make_query_by_flag(BUS::FLAG::TRANSMIT))) {
                goto Again;
            }

            ERROR error = NO_ERROR;

            if (!find_bus(make_query_by_flag(BUS::FLAG::UPDATING))) {
                error = transmit_etb();
            }

            if (error != NO_ERROR) {
                return err(error);
            }

            machine.state = MACHINE::STATE::SYNCHRONIZING;

            [[fallthrough]];
        }
        case MACHINE::STATE::SYNCHRONIZING: {
            if (!bitset.waiting) {
                bitset.synched = false;
            }

            const size_t old_etb = machine.etb;

            if (machine.etb < machine.peers && incoming.size) {
                ERROR error = receive();

                if (error != NO_ERROR) {
                    return err(error);
                }
            }

            if (find_bus(make_query_by_flag(BUS::FLAG::UPDATE))) {
                if (find_bus(make_query_by_flag(BUS::FLAG::RECEIVE))) {
                    machine.state = MACHINE::STATE::DESERIALIZING;

                    goto Again;
                }

                machine.state = MACHINE::STATE::SERIALIZING;

                goto Again;
            }

            if (outgoing.size || machine.etb < machine.peers) {
                if (old_etb == machine.etb) {
                    bitset.waiting = true;
                }

                return ERROR::NONE;
            }

            if (find_bus(make_query_by_flag(BUS::FLAG::UPDATING))) {
                die();
            }

            machine.state = MACHINE::STATE::DESERIALIZING;

            [[fallthrough]];
        }
        case MACHINE::STATE::DESERIALIZING: {
            if (bitset.reindex) {
                ERROR error{ reindex() };

                if (error != ERROR::NONE) {
                    return err(error);
                }
            }

            if (find_bus(make_query_by_flag(BUS::FLAG::RECEIVE))) {
                if (!bitset.alerted) {
                    bitset.alerted = true;

                    return ERROR::NONE;
                }

                return report(
                    ERROR::PENDING_ALERT,
                    "%s", "cannot proceed if there are unhandled events"
                );
            }

            if (find_bus(make_query_by_flag(BUS::FLAG::UPDATE))) {
                machine.state = MACHINE::STATE::SERIALIZING;

                goto Again;
            }

            machine.state = MACHINE::STATE::FINALIZING;

            [[fallthrough]];
        }
        case MACHINE::STATE::FINALIZING: {
            BUS *bus;

            while ( (bus = find_bus(make_query_by_flag(BUS::FLAG::RECYCLE))) ) {
                rem_flag(*bus, BUS::FLAG::RECYCLE);

                if (bus->next.machine.id == machine.id) {
                    set_flag(*bus, BUS::FLAG::UPDATE);
                }

                bus->machine.id = bus->next.machine.id;

                BUS *master = find_master(*bus);

                if (master && bus->bitset.serialized) {
                    if (master->rank.slaves.serialized == 0) {
                        die();
                    }

                    --master->rank.slaves.serialized;
                }

                bus->bitset.serialized = false;
            }

            machine.etb = 0;

            break;
        }
        default: break;
    }

    return err(ERROR::NONE);
}

inline DATABUS::ALERT DATABUS::next_alert() noexcept {
    bitset.alerted = false;

    switch (machine.state) {
        case MACHINE::STATE::SERIALIZING: {
            for (;;) {
                BUS *const bus{
                    find_bus(make_query_by_flag(BUS::FLAG::UPDATE))
                };

                if (!bus) {
                    break;
                }

                if (bus->bitset.serialized) {
                    die();
                }

                rem_flag(*bus, BUS::FLAG::UPDATE);

                if (bus->rank.slaves.serialized < bus->rank.slaves.list.size) {
                    set_flag(*bus, BUS::FLAG::UPDATING);

                    continue;
                }

                set_flag(*bus, BUS::FLAG::RECYCLE);
                set_flag(*bus, BUS::FLAG::TRANSMIT);

                if (bus->rank.master.bus.id) {
                    BUS &master = get_bus(
                        make_query_by_id(bus->rank.master.bus.id)
                    );

                    BUS::RANK &rank = master.rank;

                    if (rank.slaves.serialized >= rank.slaves.list.size) {
                        die();
                    }

                    if (++rank.slaves.serialized == rank.slaves.list.size
                    &&  has_flag(master, BUS::FLAG::UPDATING)) {
                        rem_flag(master, BUS::FLAG::UPDATING);
                        set_flag(master, BUS::FLAG::UPDATE);
                    }
                }

                bus->bitset.serialized = true;

                DATABUS::QUERY query_blocked{
                    make_query_by_flag(BUS::FLAG::BLOCKED)
                };

                for (BUS *blocked = find_bus(query_blocked); blocked;) {
                    rem_flag(*blocked, BUS::FLAG::BLOCKED);

                    bool found = false;

                    for (BUS *master = find_master(*blocked); master;) {
                        if (master == bus) {
                            found = true;
                            break;
                        }

                        master = find_master(*master);
                    }

                    if (found) {
                        set_flag(*blocked, BUS::FLAG::TRANSMIT);
                    }
                    else {
                        set_flag(*blocked, BUS::FLAG::REBLOCK);
                    }

                    blocked = find_bus(query_blocked);
                }

                DATABUS::QUERY query_reblock{
                    make_query_by_flag(BUS::FLAG::REBLOCK)
                };

                for (BUS *reblock = find_bus(query_reblock); reblock;) {
                    rem_flag(*reblock, BUS::FLAG::REBLOCK);
                    set_flag(*reblock, BUS::FLAG::BLOCKED);

                    reblock = find_bus(query_reblock);
                }

                return make_alert(bus->id, EVENT::SERIALIZE);
            }

            break;
        }
        case MACHINE::STATE::SYNCHRONIZING: {
            if (!bitset.synched) {
                bitset.synched = true;

                return make_alert(0, EVENT::SYNCHRONIZE);
            }

            break;
        }
        case MACHINE::STATE::DESERIALIZING: {
            BUS *bus = find_bus(make_query_by_flag(BUS::FLAG::RECEIVE));

            if (!bus) {
                break;
            }

            for (BUS *b = find_master(*bus); b; b = find_master(*b)) {
                if (has_flag(*b, BUS::FLAG::RECEIVE)) {
                    bus = b;
                }
            }

            rem_flag(*bus, BUS::FLAG::RECEIVE);

            return make_alert(bus->id, EVENT::DESERIALIZE);

            break;
        }
        case MACHINE::STATE::FINALIZING: {
            if (machine.etb == 0 && !bitset.waiting) {
                bitset.waiting = true;

                return make_alert(0, EVENT::FINALIZE);
            }

            break;
        }
        default: {
            break;
        }
    }

    return make_alert(0, EVENT::NONE, false);
}

inline bool DATABUS::idle() const noexcept {
    return bitset.waiting;;
}

inline void DATABUS::kick_start() noexcept {
    if (idle()) {
        if (machine.state == MACHINE::STATE::FINALIZING) {
            machine.state = MACHINE::STATE::SERIALIZING;
            bitset.waiting = false;
        }
        else if (machine.state == MACHINE::STATE::SYNCHRONIZING) {
            bitset.waiting = false;
        }
    }
}

inline size_t DATABUS::read(void *buf, size_t count) noexcept {
    if (!count) return 0;

    if (outgoing.size == 0) {
        return 0;
    }

    count = std::min(count, outgoing.size);

    if (buf) {
        std::memcpy(buf, to_uint8(outgoing), count);
    }

    if (outgoing.size > count) {
        std::memmove(
            outgoing.data, to_uint8(outgoing) + count, outgoing.size - count
        );
    }

    outgoing.size -= count;
    bitset.waiting = false;

    return count;
}

inline size_t DATABUS::peek(const void **buf) const noexcept {
    const size_t size = outgoing.size;

    if (buf) {
        *buf = size > 0 ? to_uint8(outgoing) : nullptr;
    }

    return size;
}

inline DATABUS::ERROR DATABUS::write(const void *buf, size_t count) noexcept {
    if (!buf) {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    if (count) {
        ERROR error{
            append(incoming, reinterpret_cast<const uint8_t *>(buf), count)
        };

        if (error != NO_ERROR && error != OUT_OF_MEMORY) {
            return (
                fuse() ? (
                    report(error, "%s: %s", __FUNCTION__, to_string(error))
                ) : error
            );
        }

        if (!error) {
            bitset.waiting = false;
        }

        return error;
    }

    return ERROR::NONE;
}

inline size_t DATABUS::reserve(size_t count) noexcept {
    if (count > capacity()) {
        ERROR error = reserve(incoming, incoming.size + count);

        if (error != NO_ERROR && error != OUT_OF_MEMORY) {
            if (fuse()) {
                report(error, "%s: %s", __FUNCTION__, to_string(error));
            }
        }
    }

    return capacity();
}

inline size_t DATABUS::capacity() noexcept {
    return incoming.capacity - incoming.size;
}

uint64_t DATABUS::next_random() noexcept {
    return (
        random = (164603309694725029ull * random) % 14738995463583502973ull
    );
}

inline DATABUS::ERROR DATABUS::create_entry(
    size_t id, const void *data, size_t size
) noexcept {
    if (id == 0) {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    ERROR error = NO_ERROR;

    if (find_bus(make_query_by_id(id))) {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    const BUS copy_from{
        make_bus(id, make_pipe(data, size, PIPE::TYPE::C_STR))
    };

    error = capture(copy_from);

    if (!error) {
        get_bus(make_query_by_id(id)).machine.id = machine.id;
    }

    return error;
}

inline DATABUS::ERROR DATABUS::update_entry(
    size_t id, const void *data, size_t size
) noexcept {
    if (id == 0) {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    ERROR error = NO_ERROR;

    BUS *bus = find_bus(make_query_by_id(id));

    if (bus) {
        const PIPE payload_wrapper{make_pipe(data, size, PIPE::TYPE::C_STR)};

        error = copy(payload_wrapper, bus->payload);
    }
    else {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    return error;
}

inline DATABUS::ERROR DATABUS::delete_entry(size_t id) noexcept {
    if (id == 0) {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    ERROR error = NO_ERROR;

    BUS *bus = find_bus(make_query_by_id(id));

    if (bus) {
        error = transfer(*bus, nullptr);

        if (!error) {
            const PIPE &contents = bus->rank.slaves.list;

            while (contents.size) {
                error = delete_entry(to_bus(get_last(contents))->id);

                if (error != NO_ERROR) {
                    die();
                }
            }

            release(bus);
        }
    }
    else {
        return fuse() ? report_bad_request() : ERROR::BAD_REQUEST;
    }

    return error;
}

inline DATABUS::ERROR DATABUS::set_entry(
    size_t id, const void *data, size_t size, const char *file, int line
) noexcept {
    if (id == 0) {
        return (
            fuse() ? (
                report_bad_request("cannot set ID zero", file, line)
            ) : ERROR::BAD_REQUEST
        );
    }

    if (machine.state != MACHINE::STATE::SERIALIZING) {
        return (
            fuse() ? (
                report_bad_request("cannot set unless serializing", file, line)
            ) : ERROR::BAD_REQUEST
        );
    }

    BUS *bus = find_bus(make_query_by_id(id));

    if (bus) {
        if (domain(*bus) != machine.id) {
            return (
                fuse() ? (
                    report_bad_request("cannot set a foreign entry", file, line)
                ) : ERROR::BAD_REQUEST
            );
        }
    }

    ERROR error = NO_ERROR;

    if (bus) {
        const bool changed{
            bus->payload.size != size ||
            std::memcmp(to_char(bus->payload), data, size)
        };

        error = update_entry(id, data, size);

        if (!error) {
            if (changed) {
                bus->bitset.changed = true;
                set_flag(*bus, BUS::FLAG::TRANSMIT);
            }

            return NO_ERROR;
        }
    }
    else {
        error = create_entry(id, data, size);

        if (!error) {
            bus = &get_bus(make_query_by_id(id));
            set_flag(*bus, BUS::FLAG::UPDATE);
            bus->bitset.changed = true;
        }
    }

    return error;
}

inline DATABUS::ERROR DATABUS::set_entry(
    size_t id, const char *data, const char *file, int line
) noexcept {
    return set_entry(id, data, std::strlen(data), file, line);
}

inline DATABUS::ERROR DATABUS::transfer(BUS &bus, BUS *master) noexcept {
    BUS *old_master = nullptr;

    if (bus.rank.master.bus.id) {
        old_master = find_bus(make_query_by_id(bus.rank.master.bus.id));

        if (!old_master) {
            die();
        }
    }

    size_t old_index = bus.rank.index;

    if (master) {
        if (master == old_master) {
            return NO_ERROR;
        }

        size_t new_index = master->rank.slaves.list.size;

        ERROR error{
            insert(master->rank.slaves.list, make_pipe_entry(&bus))
        };

        if (error != ERROR::NONE) {
            return error;
        }

        bus.rank.master.bus.id = master->id;
        bus.rank.index  = new_index;

        if (bus.bitset.serialized) {
            const size_t limit = master->rank.slaves.list.size;

            if (master->rank.slaves.serialized >= limit) {
                die();
            }

            ++master->rank.slaves.serialized;
        }
    }

    if (old_master) {
        erase(old_master->rank.slaves.list, old_index);

        if (old_master->rank.slaves.list.size > old_index) {
            BUS *other = to_bus(
                get_entry(old_master->rank.slaves.list, old_index)
            );

            if (!other) die();

            other->rank.index = old_index;
        }

        if (bus.bitset.serialized) {
            if (master->rank.slaves.serialized == 0) {
                die();
            }

            --old_master->rank.slaves.serialized;
        }

        bus.rank.index = 0;
        bus.rank.master.bus.id = 0;
    }

    return NO_ERROR;
}

inline DATABUS::ERROR DATABUS::set_container(
    size_t id, size_t container_id, const char *file, int line
) noexcept {
    if (machine.state != MACHINE::STATE::SERIALIZING) {
        return (
            fuse() ? (
                report_bad_request(
                    "cannot set container unless serializing", file, line
                )
            ) : ERROR::BAD_REQUEST
        );
    }

    BUS *bus = find_bus(make_query_by_id(id));

    if (!bus) {
        return (
            fuse() ? (
                report_bad_request("cannot nest non-existent entry", file, line)
            ) : ERROR::BAD_REQUEST
        );
    }

    if (bus
    && domain(*bus) != machine.id
    && !has_flag(*bus, BUS::FLAG::UPDATE)) {
        return (
            fuse() ? (
                report_bad_request(
                    "cannot transfer a foreign entry", file, line
                )
            ) : ERROR::BAD_REQUEST
        );
    }

    BUS *new_container = find_bus(make_query_by_id(container_id));

    if (container_id && !new_container) {
        return (
            fuse() ? (
                report_bad_request(
                    "cannot transfer entry into a non-existent entry",
                    file, line
                )
            ) : ERROR::BAD_REQUEST
        );
    }

    if (new_container
    && domain(*new_container) != machine.id
    && !has_flag(*new_container, BUS::FLAG::UPDATE)) {
        return (
            fuse() ? (
                report_bad_request(
                    "cannot transfer entry into a foreign entry", file, line
                )
            ) : ERROR::BAD_REQUEST
        );
    }

    BUS *old_container = nullptr;

    if (bus->rank.master.bus.id) {
        old_container = find_bus(make_query_by_id(bus->rank.master.bus.id));

        if (!old_container) {
            return (
                fuse() ? (
                    report_bad_request("unexpectedly missing nest", file, line)
                ) : ERROR::BAD_REQUEST
            );
        }

        if (domain(*old_container) != machine.id) {
            return (
                fuse() ? (
                    report_bad_request(
                        "cannot remove entry from a foreign container",
                        file, line
                    )
                ) : ERROR::BAD_REQUEST
            );
        }
    }

    if (new_container) {
        for (size_t nest_id = new_container->id; nest_id;) {
            if (nest_id == id) {
                return (
                    fuse() ? (
                        report_bad_request(
                            "cannot insert entry into itself", file, line
                        )
                    ) : ERROR::BAD_REQUEST
                );
            }

            nest_id = get_bus(make_query_by_id(nest_id)).rank.master.bus.id;
        }
    }

    if (new_container == old_container) {
        return NO_ERROR;
    }

    ERROR error = transfer(*bus, new_container);

    if (!error) {
        if (new_container != old_container) {
            set_flag(*bus, BUS::FLAG::TRANSMIT);
            bus->bitset.changed = true;
        }
    }

    return error;
}

inline size_t DATABUS::get_container(
    size_t id, const char *file, int line
) const noexcept {
    const BUS *bus = find_bus(make_query_by_id(id));

    if (!bus) {
        report_bad_request(
            "cannot get the container of a nonexistent content", file, line
        );

        return 0;
    }

    return bus->rank.master.bus.id;
}

inline size_t DATABUS::get_content(
    size_t id, size_t index, const char *file, int line
) const noexcept {
    const BUS *bus = find_bus(make_query_by_id(id));

    if (!bus) {
        report_bad_request(
            "cannot get the contents of a nonexistent container", file, line
        );

        return 0;
    }

    const PIPE &contents = bus->rank.slaves.list;

    return index >= contents.size ? 0 : to_bus(get_entry(contents, index))->id;
}

inline DATABUS::ENTRY DATABUS::get_entry(size_t id) const noexcept {
    const BUS *bus = find_bus(make_query_by_id(id));

    if (!bus) {
        return make_entry(ERROR::NONE);
    }

    return make_entry(bus->id, bus->payload.size, bus->payload.data);
}

inline decltype(DATABUS::BUS::machine.id) DATABUS::domain(
    const BUS &bus
) const noexcept {
    const BUS *last_serialized = nullptr;

    for (const BUS *b = &bus; b; b = find_master(*b)) {
        if (!b->bitset.serialized) {
            continue;
        }

        last_serialized = b;
    }

    if (last_serialized) {
        return last_serialized->machine.id;
    }

    return 0;
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
    ERROR error, int line, const char *file, char const *function
) const noexcept {
    return report(
        error, "%s: %s (%s:%d)", function, to_string(error), file, line
    );
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
            else if (log_userdata_callback) {
                log_userdata_callback(error, bufptr, log_userdata);
            }
            else {
                if (::write(STDERR_FILENO, bufptr, strlen(bufptr)) > 0) {
                    (void)!::write(STDERR_FILENO, "\n", 1);
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
                else if (log_userdata_callback) {
                    log_userdata_callback(error, OOM, log_userdata);
                }
                else {
                    if (::write(STDERR_FILENO, OOM, strlen(OOM)) > 0) {
                        (void)!::write(STDERR_FILENO, "\n", 1);
                    }
                }
            }
        }
        else {
            if (log_callback) {
                log_callback(error, bufptr);
            }
            else if (log_userdata_callback) {
                log_userdata_callback(error, bufptr, log_userdata);
            }
            else {
                if (::write(STDERR_FILENO, bufptr, strlen(bufptr)) > 0) {
                    (void)!::write(STDERR_FILENO, "\n", 1);
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
    if (copy.id == 0) {
        return fuse() ? report_bug() : ERROR::LIBRARY;
    }

    if (find_bus(make_query_by_id(copy.id))) {
        return fuse() ? report_bug() : ERROR::LIBRARY;
    }

    for (auto &ev : copy.flag_lookup) {
        ERROR error{
            reserve(
                INDEX::TYPE::FLAG_TO_BUS,
                make_key(static_cast<BUS::FLAG>(&ev - &(copy.flag_lookup[0]))),
                machine.buses + 1
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
        ++machine.buses;

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

    if (transfer(*bus, nullptr) != NO_ERROR) {
        die();
    }

    while (bus->rank.slaves.list.size) {
        PIPE::ENTRY entry{get_last(bus->rank.slaves.list)};
        BUS *content = to_bus(entry);

        if (transfer(*content, nullptr) != NO_ERROR) {
            die();
        }
    }

    for (auto &ev : bus->flag_lookup) {
        rem_flag(*bus, static_cast<BUS::FLAG>(&ev - &(bus->flag_lookup[0])));
    }

    destroy(bus->payload);
    destroy(bus->rank.slaves.list);

    if (erase(INDEX::TYPE::ID_TO_BUS, make_key(bus->id))) {
        --machine.buses;
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
        case QUERY::TYPE::BUS_BY_FLAG: {
            entry = find(
                INDEX::TYPE::FLAG_TO_BUS, make_key(query.bus_flag)
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

inline const DATABUS::PIPE *DATABUS::find_buses(BUS::FLAG flg) const noexcept {
    INDEX::ENTRY entry{find(INDEX::TYPE::FLAG_TO_BUS, make_key(flg))};

    if (entry.valid) {
        return entry.val_pipe;
    }

    return nullptr;
}

inline DATABUS::BUS *DATABUS::find_master(
    const BUS &bus, BUS::FLAG flag
) const noexcept {
    const BUS *master = &bus;

    do {
        master = (
            master->rank.master.bus.id ? find_bus(
                make_query_by_id(master->rank.master.bus.id)
            ) : nullptr
        );

        if (master && has_flag(*master, flag)) {
            return const_cast<BUS *>(master);
        }
    }
    while (master);

    return nullptr;
}

inline DATABUS::BUS *DATABUS::find_master(const BUS &bus) const noexcept {
    return (
        bus.rank.master.bus.id ? find_bus(
            make_query_by_id(bus.rank.master.bus.id)
        ) : nullptr
    );
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

inline DATABUS::BUS **DATABUS::to_bus_ptr(const PIPE &pipe) const noexcept {
    if (pipe.type != PIPE::TYPE::BUS_PTR) die();

    return static_cast<BUS **>(pipe.data);
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

inline void DATABUS::set_flag(
    BUS &bus, BUS::FLAG flag, bool value, const char *file, int line
) noexcept {
    if (value == false) {
        rem_flag(bus, flag);
        return;
    }

    size_t index = static_cast<size_t>(flag);

    if (index >= std::extent<decltype(bus.flag_lookup)>::value) {
        return die();
    }

    ssize_t pos = bus.flag_lookup[index];

    if (pos >= 0) {
        return; // Already set.
    }

    INDEX::ENTRY entry{
        insert(
            INDEX::TYPE::FLAG_TO_BUS,
            make_key(flag), make_pipe_entry(&bus)
        )
    };

    if (entry.valid) {
        if (entry.index > std::numeric_limits<ssize_t>::max()) {
            // the number of buses is limited by the SSIZE_MAX.
            return die();
        }

        bus.flag_lookup[index] = static_cast<ssize_t>(entry.index);

        /*log(
            "set #%lu: %s, domain %lu, serialized %c (%s:%d)",
            bus.id, to_string(flag), domain(bus),
            bus.bitset.serialized ? '1' : '0', file, line
        );*/

        return;
    }

    report(entry.error);
    die();
}

inline void DATABUS::rem_flag(
    BUS &bus, BUS::FLAG flag, const char *file, int line
) noexcept {
    size_t index = static_cast<size_t>(flag);

    if (index >= std::extent<decltype(bus.flag_lookup)>::value) {
        return die();
    }

    ssize_t pos = bus.flag_lookup[index];

    if (pos < 0) {
        return;
    }

    size_t erased = erase(
        INDEX::TYPE::FLAG_TO_BUS,
        make_key(flag), make_pipe_entry(&bus), pos, 1
    );

    if (!erased) {
        return die();
    }

    INDEX::ENTRY entry{
        find(INDEX::TYPE::FLAG_TO_BUS, make_key(flag), {}, pos, 1)
    };

    if (entry.valid && entry.index == static_cast<size_t>(pos)) {
        BUS *other_bus = to_bus(get_value(entry));
        other_bus->flag_lookup[index] = pos;
    }

    bus.flag_lookup[index] = -1;

    /*log(
        "rem #%lu: %s, domain %lu (%s:%d)",
        bus.id, to_string(flag), domain(bus), file, line
    );*/
}

inline bool DATABUS::has_flag(const BUS &bus, BUS::FLAG flag) const noexcept {
    size_t index = static_cast<size_t>(flag);

    if (index >= std::extent<decltype(bus.flag_lookup)>::value) {
        return false;
    }

    return bus.flag_lookup[index] >= 0;
}

inline DATABUS::ERROR DATABUS::transmit(
    std::initializer_list<uint64_t> headers, const void *data, size_t size
) noexcept {
    if (!machine.peers) {
        return NO_ERROR;
    }

    if (!data) {
        size = 0;
    }

    size_t packet_size = std::accumulate(
        headers.begin(), headers.end(), size,
        [](size_t sum, uint64_t h) {
            return sum + encode(h);
        }
    );

    const size_t undo_size = outgoing.size;
    ERROR error = reserve(outgoing, encode(packet_size) + packet_size);

    if (!error) {
        std::array<uint8_t, 10> buf;

        size_t len = encode(packet_size, buf);

        if (len) {
            error = append(outgoing, buf.data(), len);

            for (auto &h : headers) {
                len = encode(h, buf);

                if (len) {
                    error = append(outgoing, buf.data(), len);
                }
                else error = report_bug();

                if (error != NO_ERROR) {
                    break;
                }
            }

            if (size) {
                error = append(
                    outgoing, reinterpret_cast<const uint8_t *>(data), size
                );
            }
        }
        else error = report_bug();
    }

    if (error != NO_ERROR) {
        outgoing.size = undo_size;
    }
    else if (outgoing.size > undo_size) {
        bitset.waiting = false;
    }

    return error;
}

inline DATABUS::ERROR DATABUS::transmit(const BUS &bus) noexcept {
    return transmit(
        {
            static_cast<uint64_t>(PACKET::TYPE::ENTRY),
            bus.machine.id, bus.next.machine.id, bus.id,
            bus.rank.master.bus.id,
            to_uint64(bus.bitset)
        },
        reinterpret_cast<const uint8_t *>(to_char(bus.payload)),
        bus.payload.size
    );
}

inline DATABUS::ERROR DATABUS::receive() noexcept {
    ERROR error = NO_ERROR;
    const uint8_t *message = to_uint8(incoming);
    size_t received = 0;

    for (;;) {
        uint64_t msglen = 0;
        size_t lenlen = decode(
            message + received, incoming.size - received, &msglen
        );

        if (!lenlen) {
            break;
        }

        if (lenlen + msglen > incoming.size) {
            break;
        }

        uint64_t msgtype = 0;
        size_t parsed = received + lenlen;
        size_t decoded = decode(
            message + parsed, incoming.size - parsed, &msgtype
        );

        if (!decoded) {
            error = fuse() ? report_bug() : LIBRARY_ERROR;

            break;
        }

        parsed += decoded;

        size_t payload_len = std::min(msglen - decoded, incoming.size - parsed);

        switch (static_cast<PACKET::TYPE>(msgtype)) {
            case PACKET::TYPE::ENTRY: {
                error = receive_entry(message + parsed, payload_len);

                break;
            }
            case PACKET::TYPE::ETB: {
                error = receive_etb(message + parsed, payload_len);

                break;
            }
            default: {
                error = report_bug();

                break;
            }
        }

        if (error != NO_ERROR) {
            break;
        }

        received += lenlen + msglen;

        if (static_cast<PACKET::TYPE>(msgtype) == PACKET::TYPE::ETB
        && machine.etb == machine.peers) {
            break;
        }
    }

    if (received) {
        if (incoming.size > received) {
            std::memmove(
                incoming.data,
                to_uint8(incoming) + received, incoming.size - received
            );
        }

        incoming.size -= received;
    }

    return error;
}

inline DATABUS::ERROR DATABUS::receive_etb(
    const uint8_t *data, size_t len
) noexcept {
    uint64_t value = 0;
    size_t decoded = decode(data, len, &value);

    if (decoded) {
        ++machine.etb;
    }
    else return report_bug();

    return NO_ERROR;
}

inline DATABUS::ERROR DATABUS::receive_entry(
    const uint8_t *data, size_t len
) noexcept {
    uint64_t value = 0;
    size_t decoded = decode(data, len, &value);

    if (!decoded) {
        return report_bug();
    }
    else {
        data += decoded;
        len -= decoded;
    }

    if (value > std::numeric_limits<decltype(BUS::machine.id)>::max()) {
        return report_bug();
    }

    if (value > machine.nodes) {
        return report_bug();
    }

    if (!value) {
        return report_bug();
    }

    const auto owner = static_cast<decltype(BUS::machine.id)>(value);

    decoded = decode(data, len, &value);

    if (!decoded) {
        return report_bug();
    }
    else {
        data += decoded;
        len -= decoded;
    }

    if (value > std::numeric_limits<decltype(BUS::next.machine.id)>::max()) {
        return report_bug();
    }

    if (value > machine.nodes) {
        return report_bug();
    }

    if (!value) {
        return report_bug();
    }

    const auto next_owner{
        static_cast<decltype(BUS::next.machine.id)>(value)
    };

    decoded = decode(data, len, &value);

    if (!decoded) {
        return report_bug();
    }
    else {
        data += decoded;
        len -= decoded;
    }

    if (!value) {
        return report_bug();
    }

    const size_t bus_id = value;

    decoded = decode(data, len, &value);

    if (!decoded) {
        return report_bug();
    }
    else {
        data += decoded;
        len -= decoded;
    }

    const size_t new_master_id = value;

    decoded = decode(data, len, &value);

    if (!decoded) {
        return report_bug();
    }
    else {
        data += decoded;
        len -= decoded;
    }

    const BUS::BITSET bitset{ to_bus_bitset(value) };
    BUS *new_master = nullptr;

    if (!bitset.serialized) {
        log("received entry #%lu has not been serialized", bus_id);
        die();
    }

    if (new_master_id) {
        new_master = find_bus(make_query_by_id(new_master_id));

        if (!new_master) {
            log("container #%lu not found for #%lu", new_master_id, bus_id);
            die();
        }
    }

    ERROR error = NO_ERROR;
    BUS *bus = find_bus(make_query_by_id(bus_id));

    if (bus) {
        if (bus->machine.id != owner) {
            log(
                "bus #%lu has machine ID %lu but receives it as %lu",
                bus->id, bus->machine.id, owner
            );

            die();
        }

        if (bus->machine.id == machine.id
        && !bus->bitset.serialized
        && !domain(*bus)) {
            // We are yet to serialize this bus but some other peer is already
            // sending us an update. This is illegal and implies that there is a
            // fatal software bug in this library or that some peer has created
            // a new database entry with an already existing primary key.

            log(
                "conflicting #%lu has domain %lu (%lu)", bus->id, domain(*bus),
                bus->machine.id
            );

            die();
        }

        if (bus->payload.size       == len
        &&  bus->rank.master.bus.id == new_master_id
        &&  bus->machine.id         == owner
        &&  bus->next.machine.id    == next_owner
        &&  to_uint64(bitset)       == to_uint64(bus->bitset)
        && !std::memcmp(to_char(bus->payload), data, len)) {
            // This is supposed to be a rare but valid scenario. For example, if
            // this entry has been modified by its parent but then it is changed
            // back to the original value by its grandparent all within the same
            // databus instance, then other databus instances may receive such
            // an update that doesn't really change anything.

            return NO_ERROR;
        }

        BUS *old_master{
            bus->rank.master.bus.id ? (
                &get_bus(make_query_by_id(bus->rank.master.bus.id))
            ) : nullptr
        };

        error = transfer(*bus, new_master);

        if (!error) {
            error = update_entry(bus_id, data, len);

            if (error != NO_ERROR) {
                // Let's transfer it back to its original master.

                error = transfer(*bus, old_master);

                if (error != NO_ERROR) {
                    // Transferring the bus immediately back into its original
                    // master should never fail because the memory needed for
                    // it is already supposed to be allocated.

                    die();
                }
            }
        }
    }
    else {
        error = create_entry(bus_id, data, len);

        if (!error) {
            error = transfer(get_bus(make_query_by_id(bus_id)), new_master);

            if (error != NO_ERROR) {
                if (delete_entry(bus_id) != NO_ERROR) {
                    die();
                }
            }
        }
    }

    if (error != NO_ERROR) {
        return error;
    }

    if (!bus && (bus = find_bus(make_query_by_id(bus_id))) == nullptr) {
        die();
    }

    if (!bus->bitset.serialized && bitset.serialized) {
        BUS *master = find_master(*bus);
        BUS::RANK *rank = master ? &master->rank : nullptr;

        if (rank) {
            if (rank->slaves.serialized >= rank->slaves.list.size) {
                die();
            }

            if (++rank->slaves.serialized == rank->slaves.list.size) {
                if (has_flag(*master, BUS::FLAG::UPDATING)) {
                    rem_flag(*master, BUS::FLAG::UPDATING);
                    set_flag(*master, BUS::FLAG::UPDATE);
                }
            }
        }
    }

    bus->bitset = bitset;

    set_flag(*bus, BUS::FLAG::RECEIVE);
    set_flag(*bus, BUS::FLAG::RECYCLE);

#ifdef DATABUS_DEBUG
    if (has_flag(*bus, BUS::FLAG::UPDATE)) die();
    if (bus->bitset.changed) die();
#endif

    bus->machine.id = owner;
    bus->next.machine.id = next_owner;

    return error;
}

inline DATABUS::ERROR DATABUS::transmit_etb() noexcept {
    return transmit(
        { static_cast<uint64_t>(PACKET::TYPE::ETB), machine.id }
    );
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

    return append(dst, src);
}

inline DATABUS::ERROR DATABUS::append(PIPE &dst, const PIPE &src) noexcept {
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

inline DATABUS::ERROR DATABUS::append(
    PIPE &dst, const uint8_t *src, size_t len
) noexcept {
    return append(dst, make_pipe(src, len));
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
    return DATABUS::KEY{
        .value = val
    };
}

constexpr DATABUS::KEY DATABUS::make_key(BUS::FLAG val) noexcept {
    return make_key(static_cast<uintptr_t>(val));
}

constexpr DATABUS::RESULT DATABUS::make_result(
    int value, int code, ERROR error,
    const char *text, const char *call, const char *file, int line
) noexcept {
    return RESULT{
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
    BUS bus{
        .id{id},
        .flag_lookup{},
        .payload{payload},
        .rank{make_bus_rank()},
        .machine{},
        .next{},
        .bitset{}
    };

    for (auto &lookup_value : bus.flag_lookup) {
        lookup_value = -1;
    }

    return bus;
}

constexpr DATABUS::BUS::RANK DATABUS::make_bus_rank() noexcept {
    return BUS::RANK{
        .index{},
        .master{},
        .slaves{ .serialized{}, .list{make_pipe(PIPE::TYPE::BUS_PTR)} }
    };
}

constexpr DATABUS::MEMPOOL DATABUS::make_mempool() noexcept {
    return DATABUS::MEMPOOL{
        .free  = {},
        .list  = nullptr,
        .usage = 0,
        .top   = 0,
        .cap   = std::numeric_limits<decltype(MEMPOOL::cap)>::max(),
        .oom   = false
    };
}

constexpr DATABUS::MACHINE DATABUS::make_machine() noexcept {
    return DATABUS::MACHINE{
        .nodes = {1},
        .peers = {0},
        .buses = {},
        .etb   = {},
        .id    = {1},
        .state = {}
    };
}

constexpr DATABUS::ALERT DATABUS::make_alert(
    size_t entry, EVENT event, bool valid
) noexcept {
    return ALERT{
        .entry = entry,
        .event = event,
        .valid = valid
    };
}

constexpr DATABUS::ENTRY DATABUS::make_entry(
    size_t id, size_t size, void *data, ERROR error, bool valid
) noexcept {
    return ENTRY{
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
    return DATABUS::INDEX::ENTRY{
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
    return DATABUS::PIPE{
        .capacity = size,
        .size = size,
        .data = const_cast<void *>(data),
        .type = type,
        .memory = nullptr
    };
}

constexpr DATABUS::PIPE DATABUS::make_pipe(PIPE::TYPE type) noexcept {
    return DATABUS::PIPE{
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
    return DATABUS::PIPE::ENTRY{
        .as_uint64 = value,
        .type = PIPE::TYPE::UINT64
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    KEY value
) noexcept {
    return DATABUS::PIPE::ENTRY{
        .as_key = value,
        .type = PIPE::TYPE::KEY
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    BUS *value
) noexcept {
    return DATABUS::PIPE::ENTRY{
        .as_ptr = value,
        .type = PIPE::TYPE::BUS_PTR
    };
}

constexpr struct DATABUS::PIPE::ENTRY DATABUS::make_pipe_entry(
    MEMORY *value
) noexcept {
    return DATABUS::PIPE::ENTRY{
        .as_ptr = value,
        .type = PIPE::TYPE::MEMORY_PTR
    };
}

constexpr struct DATABUS::QUERY DATABUS::make_query_by_flag(
    BUS::FLAG flag
) noexcept {
    return QUERY{
        .bus_flag = flag,
        .type = QUERY::TYPE::BUS_BY_FLAG
    };
}

constexpr struct DATABUS::QUERY DATABUS::make_query_by_id(
    size_t bus_id
) noexcept {
    return QUERY{
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

constexpr const char *DATABUS::to_string(EVENT event) noexcept {
    switch (event) {
        case EVENT::NONE:          return "no event";
        case EVENT::SYNCHRONIZE:   return "synchronization";
        case EVENT::DESERIALIZE:   return "deserialization";
        case EVENT::SERIALIZE:     return "serialization";
        case EVENT::FINALIZE:      return "finalization";
        case EVENT::MAX_EVENTS:    return "illegal event";
    }

    return "undefined event";
}

constexpr const char *DATABUS::to_string(BUS::FLAG flag) noexcept {
    switch (flag) {
        case BUS::FLAG::NONE:         return "no flag";
        case BUS::FLAG::RECEIVE:      return "receive";
        case BUS::FLAG::UPDATING:     return "updating";
        case BUS::FLAG::UPDATE:       return "update";
        case BUS::FLAG::TRANSMIT:     return "transmit";
        case BUS::FLAG::TRANSMITTING: return "transmitting";
        case BUS::FLAG::RECYCLE:      return "recycle";
        case BUS::FLAG::BLOCKED:      return "blocked";
        case BUS::FLAG::REBLOCK:      return "reblock";
        case BUS::FLAG::MAX_FLAGS:    return "illegal flag";
    }

    return "undefined flag";
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

constexpr uint64_t DATABUS::nbo64(uint64_t val) noexcept {
    static_assert(
        (
            std::endian::native == std::endian::big ||
            std::endian::native == std::endian::little
        ),
        "mixed-endian processors are not supported"
    );

    if constexpr (std::endian::native == std::endian::little) {
        return std::byteswap(val);
    }

    return val;
}

inline size_t DATABUS::encode(
    uint64_t num, std::array<uint8_t, 10> &buf
) noexcept {
    for (size_t pos = 0; pos < buf.size();) {
        uint8_t oct = num & 0x7f;
        num >>= 7;

        if (!num) {
            buf[pos++] = 0x80 | oct;

            return pos;
        }

        buf[pos++] = oct;
        --num;
    }

    return 0;
}

inline size_t DATABUS::encode(uint64_t num, void *out, size_t len) noexcept {
    std::array<uint8_t, 10> buf;

    size_t ret = encode(num, buf);

    if (ret <= len) {
        if (out) {
            std::memcpy(out, buf.data(), ret);
        }

        return ret;
    }

    return 0;
}

inline size_t DATABUS::decode(
    const void *in, size_t len, uint64_t *out
) noexcept {
    uint64_t shift = 1;
    uint64_t num = 0;

    for (size_t pos =0; pos < len;) {
        uint8_t oct = static_cast<const uint8_t *>(in)[pos++];

        num += (oct & 0x7f) * shift;

        if (oct & 0x80) {
            if (out) {
                *out = num;
            }

            return pos;
        }

        shift <<= 7;
        num += shift;
    }

    return 0;
}

inline uint64_t DATABUS::to_uint64(DATABUS::BUS::BITSET bitset) noexcept {
    uint64_t value = 0;

    if (bitset.serialized) value |= 1;

    return value;
}

inline DATABUS::BUS::BITSET DATABUS::to_bus_bitset(uint64_t value) noexcept {
    BUS::BITSET bitset{};

    if (value & 1) bitset.serialized = true;

    return bitset;
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

inline uint16_t DATABUS::crc16(
    uint16_t crc, const void *mem, size_t len
) noexcept {
    const unsigned char *data = static_cast<const unsigned char *>(mem);

    if (!data) {
        return 0;
    }

    for (size_t i=0; i<len; i++) {
        crc ^= data[i];

        for (unsigned k=0; k<8; k++) {
            crc = crc & 1 ? (crc >> 1) ^ 0xa001 : crc >> 1;
        }
    }

    return crc;
}

static_assert(
    __LINE__ < sizeof(DATABUS::fuses) * DATABUS::BITS_PER_BYTE,
    "number of fuse bits should exceed the line count of this file"
);

#endif
