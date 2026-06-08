package main

import "encoding/binary"

// ParseSNI 从一个 TLS ClientHello 记录中提取 server_name 扩展里的 host_name。
// 返回 (host, true) 命中；(其它, false) 表示非 TLS / 无 SNI / 截断。
func ParseSNI(b []byte) (string, bool) {
	// TLS record: type(1)=0x16 handshake, version(2), length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return "", false
	}
	rec := int(binary.BigEndian.Uint16(b[3:5]))
	hs := b[5:]
	if len(hs) < rec || rec < 4 {
		return "", false
	}
	hs = hs[:rec]
	// Handshake: msg_type(1)=0x01 ClientHello, length(3)
	if hs[0] != 0x01 {
		return "", false
	}
	p := hs[4:]
	// version(2) + random(32)
	if len(p) < 34 {
		return "", false
	}
	p = p[34:]
	// session_id: len(1)+data
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", false
	}
	p = p[1+int(p[0]):]
	// cipher_suites: len(2)+data
	if len(p) < 2 {
		return "", false
	}
	cs := int(binary.BigEndian.Uint16(p[0:2]))
	if len(p) < 2+cs {
		return "", false
	}
	p = p[2+cs:]
	// compression_methods: len(1)+data
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", false
	}
	p = p[1+int(p[0]):]
	// extensions: len(2)+data
	if len(p) < 2 {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < extTotal {
		return "", false
	}
	p = p[:extTotal]
	for len(p) >= 4 {
		etype := binary.BigEndian.Uint16(p[0:2])
		elen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < elen {
			return "", false
		}
		ext := p[:elen]
		p = p[elen:]
		if etype != 0x0000 { // server_name
			continue
		}
		// server_name_list: len(2), then entries: type(1)+namelen(2)+name
		if len(ext) < 2 {
			return "", false
		}
		sn := ext[2:]
		for len(sn) >= 3 {
			nameType := sn[0]
			nl := int(binary.BigEndian.Uint16(sn[1:3]))
			sn = sn[3:]
			if len(sn) < nl {
				return "", false
			}
			if nameType == 0x00 { // host_name
				return string(sn[:nl]), true
			}
			sn = sn[nl:]
		}
	}
	return "", false
}
