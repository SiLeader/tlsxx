//
// Created by cerussite on 2019/11/28.
//

#pragma once

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <array>
#include <iomanip>
#include <sstream>
#include <tlsxx/detail/bit.hpp>
#include <tlsxx/detail/iterator.hpp>

namespace tlsxx::hash {
    class md5 {
    private:
#define B(n) static_cast<std::byte>(n)
        std::array<std::byte, 4 * 4> _current = {
            B(0x01), B(0x23), B(0x45), B(0x67), B(0x89), B(0xab), B(0xcd), B(0xef),
            B(0xfe), B(0xdc), B(0xba), B(0x98), B(0x76), B(0x54), B(0x32), B(0x10),
        };
#undef B
        std::vector<std::byte> _message;

    public:
        template <class InputIterator,
                  class = tlsxx::detail::requires_input_iterator<InputIterator>>
        md5(InputIterator first, InputIterator last) {
            update(first, last);
        }

        template <class T>
        explicit md5(const T &t)
            : md5(std::begin(t), std::end(t)) {}

        template <class V>
        md5(std::initializer_list<V> il)
            : md5(std::begin(il), std::end(il)) {}

    public:
        template <class InputIterator,
                  class = tlsxx::detail::requires_input_iterator<InputIterator>>
        void update(InputIterator first, InputIterator last) {
            using pointer_type = typename std::iterator_traits<InputIterator>::pointer;
            using value_type = typename std::iterator_traits<InputIterator>::value_type;

            std::for_each(first, last, [this](const value_type &value) {
                auto ptr = static_cast<const std::byte *>(static_cast<const void *>(&value));
                _message.insert(std::end(_message), ptr, ptr + sizeof(value));
            });
        }

        template <class T> void update(const T &t) { update(std::begin(t), std::end(t)); }

    private:
        void _do_padding() {
            static constexpr auto _1 = static_cast<std::byte>(0b10000000);
            static constexpr auto _0 = static_cast<std::byte>(0b00000000);

            _message.emplace_back(_1);
            const std::uint64_t length = std::size(_message);

            while (std::size(_message) % 64 == 56) {
                _message.emplace_back(_0);
            }

            auto lp = static_cast<const std::byte *>(static_cast<const void *>(&length));
            _message.insert(std::end(_message), lp, lp + 8);
        }

        template <class F>
        static constexpr std::uint32_t _do_round(std::uint32_t a, std::uint32_t b, std::uint32_t c,
                                                 std::uint32_t d, std::uint32_t x, std::uint32_t t,
                                                 std::size_t s, const F &f) {
            a += f(b, c, d) + x + t;
            a = detail::rotate_left(a, s);
            return a + b;
        }

    public:
        std::array<std::byte, 128 / 8> digest() {
            static constexpr std::uint32_t K[] = {
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
                0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
                0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
                0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
                0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
                0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
                0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
                0xeb86d391,
            };
            static constexpr std::size_t SHIFT_1[] = {7, 12, 17, 22};
            static constexpr std::size_t SHIFT_2[] = {5, 9, 14, 20};
            static constexpr std::size_t SHIFT_3[] = {7, 12, 17, 22};
            static constexpr std::size_t SHIFT_4[] = {7, 12, 17, 22};

            auto first = std::begin(_message);
#define J(n) detail::join<std::uint32_t>(first + n, first + n + 4)
            std::array<std::uint32_t, 16> x = {
                J(0),  J(4),  J(8),  J(12), J(16), J(20), J(24), J(28),
                J(32), J(36), J(40), J(44), J(48), J(52), J(56), J(60),
            };
#undef J

            _do_padding();

            auto ap = static_cast<std::uint32_t *>(static_cast<void *>(_current.data()));
            auto bp = static_cast<std::uint32_t *>(static_cast<void *>(_current.data() + 4));
            auto cp = static_cast<std::uint32_t *>(static_cast<void *>(_current.data() + 8));
            auto dp = static_cast<std::uint32_t *>(static_cast<void *>(_current.data() + 16));

            auto a = *ap;
            auto b = *bp;
            auto c = *cp;
            auto d = *dp;

            auto &ar = *ap;
            auto &br = *bp;
            auto &cr = *cp;
            auto &dr = *dp;

            for (std::size_t n = 0; n < 16; ++n) {
                ar = _do_round(ar, br, cr, dr, x[n], K[n + 1], SHIFT_1[n % std::size(SHIFT_1)],
                               [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
                                   return (x & y) | ((~x) & z);
                               });
            }
            for (std::size_t n = 0; n < 16; ++n) {
                ar = _do_round(ar, br, cr, dr, x[(5 * n + 1) % 16], K[n + 17],
                               SHIFT_2[n % std::size(SHIFT_2)],
                               [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
                                   return (x & z) | ((~y) & z);
                               });
            }
            for (std::size_t n = 0; n < 16; ++n) {
                ar = _do_round(
                    ar, br, cr, dr, x[(3 * n + 5) % 16], K[n + 33], SHIFT_3[n % std::size(SHIFT_3)],
                    [](std::uint32_t x, std::uint32_t y, std::uint32_t z) { return x ^ y ^ z; });
            }
            for (std::size_t n = 0; n < 16; ++n) {
                ar = _do_round(ar, br, cr, dr, x[(7 * n) % 16], K[n + 49],
                               SHIFT_4[n % std::size(SHIFT_4)],
                               [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
                                   return y ^ (x | (~z));
                               });
            }

            ar += a;
            br += b;
            cr += c;
            dr += d;

            return _current;
        }

        std::string hex_digest() {
            auto d = digest();

            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0');

            for (const auto &dd : d) {
                ss << static_cast<unsigned>(dd);
            }
            return ss.str();
        }
    };
} // namespace tlsxx::hash
