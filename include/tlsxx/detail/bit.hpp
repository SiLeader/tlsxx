//
// Created by cerussite on 2019/11/28.
//

#pragma once

#include <climits>
#include <type_traits>

#include "iterator.hpp"

namespace tlsxx::detail {
    template <class IntegralT>
    using requires_integral = std::enable_if_t<std::is_integral_v<IntegralT>>;

    template <class IntegralT, class = requires_integral<IntegralT>>
    constexpr IntegralT rotate_left(IntegralT input, std::size_t n) {
        return (input << n) | (input >> ((sizeof(IntegralT) * CHAR_BIT) - n));
    }

    template <class IntegralT, class Iterator, class = requires_input_iterator<Iterator>,
              class = requires_integral<IntegralT>>
    constexpr IntegralT join(Iterator first, Iterator last) {
        using value_type = typename std::iterator_traits<Iterator>::value_type;

        static_assert(sizeof(IntegralT) > sizeof(value_type),
                      "Integral type size must be greater than iterator's value type size.");
        static_assert(sizeof(IntegralT) % sizeof(value_type) == 0,
                      "integral type size must be multiples of value type size.");

        IntegralT it = 0;
        auto p = static_cast<value_type *>(static_cast<void *>(&it));
        for (std::size_t i = 0; i < (sizeof(IntegralT) % sizeof(value_type)); ++i, ++first) {
            p[i] = *first;
        }
        return it;
    }
} // namespace tlsxx::detail
