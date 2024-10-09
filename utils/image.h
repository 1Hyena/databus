// SPDX-License-Identifier: MIT
#ifndef IMAGE_H_07_10_2024
#define IMAGE_H_07_10_2024

#include <png.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <limits>

struct png_buffer_type{
    const unsigned char *data;
    size_t size;
};

inline void read_png_data(
    png_structp png_ptr, png_bytep outbytes, png_size_t byte_count_to_read
) {
    png_voidp io_ptr = png_get_io_ptr(png_ptr);

    if (io_ptr == nullptr) {
        return;
    }

    // using pulsar::InputStream
    // -> replace with your own data source interface
    struct png_buffer_type *png_loader{
        reinterpret_cast<struct png_buffer_type *>(io_ptr)
    };

    if (byte_count_to_read > png_loader->size) {
        return;
    }

    std::memcpy(outbytes, png_loader->data, byte_count_to_read);

    png_loader->data += byte_count_to_read;
    png_loader->size -= byte_count_to_read;

    return;
}

void write_png_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    std::vector<unsigned char> *dest{
        reinterpret_cast<std::vector<unsigned char> *>(png_get_io_ptr(png_ptr))
    };

    if (dest == nullptr) {
        return;
    }

    dest->reserve(dest->size() + length);
    dest->insert(dest->end(), data, data + length);
}

inline auto load_png(
    const unsigned char *data, size_t size, std::vector<unsigned char> *rgba
) {
    struct return_type {
        size_t w;
        size_t h;
        const char *file;
        int line;
    } return_value;

    png_structp png = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr
    );

    if (!png) {
        return return_type{0, 0, __FILE__, __LINE__};
    }

    png_infop info = png_create_info_struct(png);

    if (!info) {
       png_destroy_read_struct(&png, nullptr, nullptr);

       return return_type{0, 0, __FILE__, __LINE__};
    }

    struct png_buffer_type png_loader{
        .data = data,
        .size = size
    };

    png_set_read_fn(png, &png_loader, read_png_data);

    png_read_info(png, info);

    return_value.w = png_get_image_width(png, info);
    return_value.h = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth  = png_get_bit_depth(png, info);

    if (bit_depth == 16) {
        png_set_strip_16(png);
    }

    if (color_type == PNG_COLOR_TYPE_PALETTE) {
        png_set_palette_to_rgb(png);
    }

    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) {
        png_set_expand_gray_1_2_4_to_8(png);
    }

    if (png_get_valid(png, info, PNG_INFO_tRNS)) {
        png_set_tRNS_to_alpha(png);
    }

    if (color_type == PNG_COLOR_TYPE_RGB
    ||  color_type == PNG_COLOR_TYPE_GRAY
    ||  color_type == PNG_COLOR_TYPE_PALETTE) {
        png_set_filler(png, 0xFF, PNG_FILLER_AFTER);
    }

    if (color_type == PNG_COLOR_TYPE_GRAY
    ||  color_type == PNG_COLOR_TYPE_GRAY_ALPHA) {
        png_set_gray_to_rgb(png);
    }

    png_read_update_info(png, info);

    png_bytep *row_pointers{
        return_value.h ? (
            (png_bytep*) malloc(sizeof(png_bytep) * return_value.h)
        ) : nullptr
    };

    if (row_pointers) {
        for (size_t y = 0; y < return_value.h; y++) {
            row_pointers[y] = (png_byte*) malloc(png_get_rowbytes(png, info));
        }

        png_read_image(png, row_pointers);
    }

    if (row_pointers && rgba) {
        for (size_t y = 0; y < return_value.h; ++y) {
            png_bytep row = row_pointers[y];

            for (size_t x = 0; x < return_value.w; ++x) {
                png_bytep px = &(row[x * 4]);

                rgba->emplace_back(px[0]);
                rgba->emplace_back(px[1]);
                rgba->emplace_back(px[2]);
                rgba->emplace_back(px[3]);
            }
        }
    }

    png_destroy_read_struct(&png, &info, nullptr);

    if (row_pointers) {
        for (size_t y = 0; y < return_value.h; y++) {
            free(row_pointers[y]);
        }

        free(row_pointers);
    }

    return return_type{
        .w = return_value.w, .h = return_value.h,
        .file = __FILE__, .line = __LINE__
    };
}

inline auto save_png(
    std::vector<unsigned char> &dest, std::vector<unsigned char> &rgba,
    size_t width
) {
    struct return_type {
        size_t written;
        const char *file;
        int line;
    };

    if (width > std::numeric_limits<png_uint_32>::max()) {
        return return_type{ 0, __FILE__, __LINE__ };
    }

    const size_t height = (rgba.size() / 4) / width;

    if (height > std::numeric_limits<png_uint_32>::max()) {
        return return_type{ 0, __FILE__, __LINE__ };
    }

    png_structp png = png_create_write_struct(
        PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr
    );

    if (!png) {
        return return_type{ 0, __FILE__, __LINE__ };
    }

    png_infop info = png_create_info_struct(png);

    if (!info) {
        return return_type{ 0, __FILE__, __LINE__ };
    }

    if (setjmp(png_jmpbuf(png))) {
        return return_type{ 0, __FILE__, __LINE__ };
    }

    png_set_write_fn(png, &dest, write_png_data, [](png_structp){});

    const size_t old_sz = dest.size();

    png_set_IHDR(
        png,
        info,
        static_cast<png_uint_32>(width), static_cast<png_uint_32>(height),
        8,
        PNG_COLOR_TYPE_RGBA,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT
    );

    png_bytep *row_pointers{
        height ? (
            (png_bytep*) malloc(sizeof(png_bytep) * height)
        ) : nullptr
    };

    if (row_pointers) {
        for (size_t y = 0; y < height; y++) {
            row_pointers[y] = (png_byte*) malloc(png_get_rowbytes(png, info));

            if (row_pointers[y]) {
                png_bytep row = row_pointers[y];

                for (size_t x = 0; x < width; ++x) {
                    png_bytep px = &(row[x * 4]);

                    px[0] = rgba[(y * width * 4) + x * 4 + 0];
                    px[1] = rgba[(y * width * 4) + x * 4 + 1];
                    px[2] = rgba[(y * width * 4) + x * 4 + 2];
                    px[3] = rgba[(y * width * 4) + x * 4 + 3];
                }
            }
            else if (y) {
                while (--y) {
                    free(row_pointers[y]);

                    if (y == 0) {
                        free(row_pointers);
                        row_pointers = nullptr;
                        y = height;

                        break;
                    }
                }
            }
        }

        if (row_pointers) {
            png_write_info(png, info);
            png_write_image(png, row_pointers);
            png_write_end(png, nullptr);

            for (size_t y = 0; y < height; y++) {
                free(row_pointers[y]);
            }

            free(row_pointers);
        }
    }

    png_destroy_write_struct(&png, &info);

    return return_type{ dest.size() - old_sz, __FILE__, __LINE__ };
}

#endif
