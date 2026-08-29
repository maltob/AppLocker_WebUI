// Generates a tiny stored ZIP containing an AppxManifest.xml entry.
(function () {
  "use strict";
  const manifest = `<?xml version="1.0" encoding="utf-8"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Contoso.Reader" Publisher="CN=Contoso Ltd, O=Contoso" Version="2.4.1.0" ProcessorArchitecture="x64" /><Properties><DisplayName>Contoso Reader</DisplayName><Publisher>Contoso Ltd</Publisher><Description>Fixture package</Description></Properties><Applications><Application Id="Reader" Executable="Contoso.Reader.exe" EntryPoint="Windows.FullTrustApplication" /></Applications></Package>`;
  function u16(bytes, offset, value) { bytes[offset] = value & 255; bytes[offset + 1] = value >>> 8 & 255; }
  function u32(bytes, offset, value) { bytes[offset] = value & 255; bytes[offset + 1] = value >>> 8 & 255; bytes[offset + 2] = value >>> 16 & 255; bytes[offset + 3] = value >>> 24 & 255; }
  window.__appxFixture = function () {
    const name = new TextEncoder().encode("AppxManifest.xml"); const data = new TextEncoder().encode(manifest); const localSize = 30 + name.length + data.length; const centralOffset = localSize; const centralSize = 46 + name.length; const output = new Uint8Array(localSize + centralSize + 22);
    u32(output, 0, 0x04034b50); u16(output, 4, 20); u16(output, 8, 0); u16(output, 26, name.length); name.forEach((value, index) => { output[30 + index] = value; }); output.set(data, 30 + name.length);
    u32(output, centralOffset, 0x02014b50); u16(output, centralOffset + 4, 20); u16(output, centralOffset + 6, 20); u16(output, centralOffset + 10, 0); u32(output, centralOffset + 20, data.length); u32(output, centralOffset + 24, data.length); u16(output, centralOffset + 28, name.length); u32(output, centralOffset + 42, 0); name.forEach((value, index) => { output[centralOffset + 46 + index] = value; });
    const eocd = centralOffset + centralSize; u32(output, eocd, 0x06054b50); u16(output, eocd + 8, 1); u16(output, eocd + 10, 1); u32(output, eocd + 12, centralSize); u32(output, eocd + 16, centralOffset); return output;
  };
})();
