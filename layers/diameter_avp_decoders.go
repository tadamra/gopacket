package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"
)

type avpDecoder interface {
	decode([]byte) error
	String() string
}

type DiameterOctetString struct {
	decodedData string
}

type DiameterInteger32 struct {
	decodedData int32
}

type DiameterInteger64 struct {
	decodedData int64
}

type DiameterUnsigned32 struct {
	decodedData uint32
}

type DiameterUnsigned64 struct {
	decodedData uint64
}

type DiameterFloat32 struct {
	decodedData float32
}

type DiameterFloat64 struct {
	decodedData float64
}

type DiameterIPAddress struct {
	decodedData net.IP
}

type DiameterTime struct {
	decodedData time.Time
}

type DiameterEnumerated struct { // vendor code?
	attributeCode uint32
	decodedData   uint32
}

func (d DiameterOctetString) Get() string { return d.decodedData }
func (d DiameterInteger32) Get() int32    { return d.decodedData }
func (d DiameterInteger64) Get() int64    { return d.decodedData }
func (d DiameterFloat32) Get() float32    { return d.decodedData }
func (d DiameterFloat64) Get() float64    { return d.decodedData }
func (d DiameterUnsigned32) Get() uint32  { return d.decodedData }
func (d DiameterUnsigned64) Get() uint64  { return d.decodedData }
func (d DiameterIPAddress) Get() net.IP   { return d.decodedData }
func (d DiameterTime) Get() time.Time     { return d.decodedData }
func (d DiameterEnumerated) Get() uint32  { return d.decodedData }

func (d DiameterOctetString) String() string { return d.decodedData }
func (d DiameterInteger32) String() string   { return strconv.Itoa(int(d.decodedData)) }
func (d DiameterInteger64) String() string   { return strconv.Itoa(int(d.decodedData)) }
func (d DiameterFloat32) String() string     { return fmt.Sprintf("%f", d.decodedData) }
func (d DiameterFloat64) String() string     { return fmt.Sprintf("%f", d.decodedData) }
func (d DiameterUnsigned32) String() string  { return strconv.FormatUint(uint64(d.decodedData), 10) }
func (d DiameterUnsigned64) String() string  { return strconv.FormatUint(uint64(d.decodedData), 10) }
func (d DiameterIPAddress) String() string   { return d.decodedData.String() }
func (d DiameterTime) String() string        { return d.decodedData.String() }
func (d DiameterEnumerated) String() string {
	return avpAttributeEnumerations[d.attributeCode][d.decodedData]
}

func (d *DiameterOctetString) decode(data []byte) error {
	dataLen := len(data)

	if dataLen == 0 {
		return errors.New("AVP contains no data to decode")
	}

	d.decodedData = string(data)

	return nil
}

func (d *DiameterInteger32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Integer32")
	}

	d.decodedData = int32(binary.BigEndian.Uint32(data))

	return nil
}

func (d *DiameterInteger64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	d.decodedData = int64(binary.BigEndian.Uint64(data))

	return nil
}

func (d *DiameterFloat32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Integer32")
	}

	d.decodedData = math.Float32frombits(binary.BigEndian.Uint32(data))

	return nil
}

func (d *DiameterFloat64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	d.decodedData = math.Float64frombits(binary.BigEndian.Uint64(data))

	return nil
}

func (d *DiameterUnsigned32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Integer32")
	}

	d.decodedData = binary.BigEndian.Uint32(data)

	return nil
}

func (d *DiameterUnsigned64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	d.decodedData = binary.BigEndian.Uint64(data)

	return nil
}

func (d *DiameterIPAddress) decode(data []byte) error {

	var ip net.IP
	// IPv4 is 4 bytes, IPv6 is 16 bytes. add 2 bytes each which is the chunk representing the type of the address (first two bits of data)
	if len(data) != 6 && len(data) != 18 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	// byte 0 and 1 will representing the type of the address which is either v4 or v6 in the IP addresses case
	ip = data[2:]
	d.decodedData = ip

	return nil
}

func (d *DiameterTime) decode(data []byte) error {

	// RFC6733 specifies Time as octetstring, but with length of 4 and uint32 defined as having network
	// byte order (big endian), it is equivalent to uint32.
	if len(data) != 4 {
		return errors.New("not enough data to decode Time")
	}
	ntp_timestamp := binary.BigEndian.Uint32(data)
	unix_timestamp := int64(ntp_timestamp) - 2208988800

	// if we see a date < year 2000, then we've overflowed into the next NTP era
	if ntp_timestamp < 3174737699 {
		unix_timestamp += int64(^uint32(0)) + 1
	}

	d.decodedData = time.Unix(unix_timestamp, 0)

	return nil
}

func (d *DiameterEnumerated) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Enumerated (Unsigned Integer32)")
	}

	d.decodedData = binary.BigEndian.Uint32(data)

	return nil
}

func getAVPFormatDecoder(avpFormat string, attributeCode uint32) avpDecoder {
	switch avpFormat {
	case "OctetString":
		return &DiameterOctetString{}
	case "Integer32":
		return &DiameterInteger32{}
	case "Integer64":
		return &DiameterInteger64{}
	case "Unsigned32":
		return &DiameterUnsigned32{}
	case "Unsigned64":
		return &DiameterUnsigned64{}
	case "Float32":
		return &DiameterFloat32{}
	case "Float64":
		return &DiameterFloat64{}
	case "DiameterIdentity":
		return &DiameterOctetString{}
	case "IPAddress":
		return &DiameterIPAddress{}
	case "UTF8String":
		return &DiameterOctetString{}
	case "AppId":
		return &DiameterUnsigned32{}
	case "VendorId":
		return &DiameterUnsigned64{}
	case "Enumerated":
		// parse value as Unsigned32, map value per attributeCode
		return &DiameterEnumerated{attributeCode: attributeCode}
	case "Time":
		return &DiameterTime{}
	case "Grouped":
		return &DiameterOctetString{}
	default:
		// TODO: add other AVP Formats covered in RFC 6733
		// IPFilterRule, DiameterURI
		return nil
	}
}
