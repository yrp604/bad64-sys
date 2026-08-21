// Copyright (c) 2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#pragma once

#include "base/unicode/ConvertUTF.h"

#include <algorithm>
#include <memory>
#include <span>
#include <stddef.h>
#include <stdint.h>

namespace bn::base {

namespace detail {

// Size of the stack buffer used during conversions. Larger output falls back to a heap buffer.
inline constexpr size_t kConvertStackBytes = 1024;

} // namespace detail

// Decodes little-endian UTF-16 bytes to UTF-8. Malformed input (unpaired surrogates) is converted
// leniently rather than rejected. The result is capped at `maxBytes`, truncated on a code point
// boundary so it is always valid UTF-8. The output string type must be provided via the String
// template parameter. Assumes a little-endian host.
template <typename String>
String UTF16ToUTF8(std::span<const uint8_t> utf16le, size_t maxBytes = String::npos)
{
	const size_t units = utf16le.size() / 2;
	// A UTF-16 code unit expands to at most 3 UTF-8 bytes.
	const size_t cap = std::min(maxBytes, units * 3);

	detail::UTF8 stackBuf[detail::kConvertStackBytes];
	std::unique_ptr<detail::UTF8[]> heapBuf;
	detail::UTF8* buf = stackBuf;
	if (cap > sizeof(stackBuf))
	{
		heapBuf = std::make_unique_for_overwrite<detail::UTF8[]>(cap);
		buf = heapBuf.get();
	}

	const auto* src = reinterpret_cast<const detail::UTF16*>(utf16le.data());
	detail::UTF8* dst = buf;
	detail::ConvertUTF16toUTF8(&src, src + units, &dst, buf + cap, detail::lenientConversion);
	return String(reinterpret_cast<const char*>(buf), static_cast<size_t>(dst - buf));
}

// Decodes little-endian UTF-32 bytes to UTF-8. Malformed input (out-of-range code points) is converted
// leniently rather than rejected. The result is capped at `maxBytes`, truncated on a code point
// boundary so it is always valid UTF-8. The output string type must be provided via the String
// template parameter. Assumes a little-endian host.
template <typename String>
String UTF32ToUTF8(std::span<const uint8_t> utf32le, size_t maxBytes = String::npos)
{
	const size_t units = utf32le.size() / 4;
	// A UTF-32 code point expands to at most 4 UTF-8 bytes.
	const size_t cap = std::min(maxBytes, units * 4);

	detail::UTF8 stackBuf[detail::kConvertStackBytes];
	std::unique_ptr<detail::UTF8[]> heapBuf;
	detail::UTF8* buf = stackBuf;
	if (cap > sizeof(stackBuf))
	{
		heapBuf = std::make_unique_for_overwrite<detail::UTF8[]>(cap);
		buf = heapBuf.get();
	}

	const auto* src = reinterpret_cast<const detail::UTF32*>(utf32le.data());
	detail::UTF8* dst = buf;
	detail::ConvertUTF32toUTF8(&src, src + units, &dst, buf + cap, detail::lenientConversion);
	return String(reinterpret_cast<const char*>(buf), static_cast<size_t>(dst - buf));
}

// Copies UTF-8 bytes truncated to at most `maxBytes`, never splitting a multi-byte sequence, so the
// result is always valid UTF-8.
template <typename String>
String TruncateUTF8(std::span<const uint8_t> utf8, size_t maxBytes)
{
	size_t end = std::min(utf8.size(), maxBytes);
	// A continuation byte at the cut means the kept prefix ends mid-sequence. Back up to its start.
	while (end > 0 && end < utf8.size() && (utf8[end] & 0xc0) == 0x80)
		end--;
	return String(reinterpret_cast<const char*>(utf8.data()), end);
}

}  // namespace bn::base
