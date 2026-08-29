// Generates a tiny, valid OLE container with a SummaryInformation stream.
// It is intentionally a browser fixture: no binary file or native helper is needed.
(function () {
  "use strict";
  function put16(bytes, offset, value) { bytes[offset] = value & 255; bytes[offset + 1] = value >>> 8 & 255; }
  function put32(bytes, offset, value) { bytes[offset] = value & 255; bytes[offset + 1] = value >>> 8 & 255; bytes[offset + 2] = value >>> 16 & 255; bytes[offset + 3] = value >>> 24 & 255; }
  function putName(bytes, offset, name) { for (let i = 0; i < name.length; i++) put16(bytes, offset + i * 2, name.charCodeAt(i)); put16(bytes, offset + name.length * 2, 0); put16(bytes, offset + 64, (name.length + 1) * 2); }
  function putWide(bytes, offset, text) { put32(bytes, offset, 31); put32(bytes, offset + 4, text.length + 1); for (let i = 0; i < text.length; i++) put16(bytes, offset + 8 + i * 2, text.charCodeAt(i)); put16(bytes, offset + 8 + text.length * 2, 0); }
  window.__msiSummaryFixture = function () {
    const bytes = new Uint8Array(1536); const header = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]; header.forEach((value, index) => { bytes[index] = value; }); put16(bytes, 28, 0xfffe); put16(bytes, 30, 9); put16(bytes, 32, 6); put32(bytes, 44, 1); put32(bytes, 48, 1); put32(bytes, 56, 0x1000); put32(bytes, 76, 0); put32(bytes, 80, 0xffffffff);
    const fat = 512; put32(bytes, fat, 0xfffffffd); put32(bytes, fat + 4, 0xfffffffe); put32(bytes, fat + 8, 0xfffffffe); for (let i = 3; i < 128; i++) put32(bytes, fat + i * 4, 0xffffffff);
    const directory = 1024; putName(bytes, directory, "Root Entry"); bytes[directory + 66] = 5; put32(bytes, directory + 68, 0xffffffff); put32(bytes, directory + 72, 0xffffffff); put32(bytes, directory + 76, 1); putName(bytes, directory + 128, "\u0005SummaryInformation"); bytes[directory + 128 + 66] = 2; put32(bytes, directory + 128 + 116, 2);
    const section = 68;
    const properties = [[2, "Contoso Installer"], [3, "Managed desktop package"], [4, "Contoso Ltd"], [18, "Windows Installer"]];
    const valuesStart = section + 8 + properties.length * 8; let cursor = valuesStart; const valueOffsets = [];
    properties.forEach(([, text]) => { valueOffsets.push(cursor - section); cursor += 8 + (text.length + 1) * 2; cursor = (cursor + 3) & ~3; });
    const summary = new Uint8Array(cursor); put16(summary, 0, 0xfffe); put16(summary, 2, 0); put32(summary, 28, 1); put32(summary, 32 + 16, section); put32(summary, section, cursor); put32(summary, section + 4, properties.length);
    properties.forEach(([id], index) => { put32(summary, section + 8 + index * 8, id); put32(summary, section + 12 + index * 8, valueOffsets[index]); }); properties.forEach(([, text], index) => putWide(summary, section + valueOffsets[index], text));
    const streamSize = summary.length; put32(bytes, directory + 128 + 120, streamSize); const output = new Uint8Array(512 * 4); output.set(bytes); output.set(summary, 1536); return output;
  };
})();
