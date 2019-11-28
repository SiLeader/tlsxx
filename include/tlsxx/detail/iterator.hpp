//
// Created by cerussite on 2019/11/28.
//

#pragma once

#include <iterator>

namespace tlsxx::detail {
    template <class Iterator>
    using iterator_category_t = typename std::iterator_traits<Iterator>::iterator_category;

    template <class Iterator, class Category>
    inline constexpr bool concept_iterator_category =
        std::is_convertible_v<iterator_category_t<Iterator>, Category>;
    template <class Iterator>
    inline constexpr bool concept_input_iterator =
        concept_iterator_category<Iterator, std::input_iterator_tag>;

    template <class Iterator>
    using requires_input_iterator = std::enable_if_t<concept_input_iterator<Iterator>>;
} // namespace tlsxx::detail
