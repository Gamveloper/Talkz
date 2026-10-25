/* Talkz Cloud — image metadata stripping (Phase 2, storage item 6).
 *
 * Removes metadata from uploaded images at upload time, in BOTH storage
 * modes (Postgres and S3), before the bytes are stored:
 *   - JPEG: every APP1..APP15 segment (EXIF, XMP, …) and COM (comment)
 *     segments are dropped. APP0 (JFIF header), quantisation/Huffman tables,
 *     frame headers and the compressed scan data are kept byte-for-byte, so
 *     the picture itself is untouched — this is a lossless segment strip,
 *     not a re-encode.
 *   - PNG: eXIf, tEXt, iTXt, zTXt and tIME chunks are dropped (EXIF data and
 *     text annotations). Critical chunks (IHDR/PLTE/IDAT/IEND) are kept.
 *   - GIF / WebP: passed through unchanged (their metadata forms are
 *     uncommon for EXIF-style geolocation; noted in ARCHITECTURE.md).
 * Non-image types are returned unchanged. Malformed images are returned
 * unchanged too — stripping must never break an otherwise valid upload.
 */

function stripJpeg(buf) {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return buf; // not SOI
  const parts = [buf.subarray(0, 2)];
  let pos = 2;
  while (pos + 4 <= buf.length) {
    if (buf[pos] !== 0xff) return buf; // malformed — bail out untouched
    const marker = buf[pos + 1];
    if (marker === 0xda) { // SOS: the rest is compressed scan data, copy verbatim
      parts.push(buf.subarray(pos));
      return Buffer.concat(parts);
    }
    if (marker === 0xd9) { parts.push(buf.subarray(pos, pos + 2)); return Buffer.concat(parts); } // EOI
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { // standalone markers, no length
      parts.push(buf.subarray(pos, pos + 2));
      pos += 2;
      continue;
    }
    const len = buf.readUInt16BE(pos + 2);
    if (len < 2 || pos + 2 + len > buf.length) return buf; // malformed
    const isAppN = marker >= 0xe1 && marker <= 0xef; // APP1..APP15
    const isComment = marker === 0xfe; // COM
    if (!isAppN && !isComment) parts.push(buf.subarray(pos, pos + 2 + len));
    pos += 2 + len;
  }
  return Buffer.concat(parts);
}

const PNG_DROP = new Set(["eXIf", "tEXt", "iTXt", "zTXt", "tIME"]);
function stripPng(buf) {
  const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (buf.length < 8 || !SIG.every((b, i) => buf[i] === b)) return buf;
  const parts = [buf.subarray(0, 8)];
  let pos = 8;
  while (pos + 12 <= buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString("latin1", pos + 4, pos + 8);
    const total = 12 + len;
    if (pos + total > buf.length) return buf; // malformed
    if (!PNG_DROP.has(type)) parts.push(buf.subarray(pos, pos + total));
    pos += total;
    if (type === "IEND") break;
  }
  if (pos < buf.length) parts.push(buf.subarray(pos)); // trailing bytes, if any
  return Buffer.concat(parts);
}

function stripImageMetadata(buffer, mime) {
  try {
    if (mime === "image/jpeg") return stripJpeg(buffer);
    if (mime === "image/png") return stripPng(buffer);
  } catch { /* fall through: return the original bytes */ }
  return buffer;
}

module.exports = { stripImageMetadata, stripJpeg, stripPng };
