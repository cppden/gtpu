#include <iostream>

#include "gtpu.hpp"
#include "med/encode.hpp"
#include "med/decode.hpp"
#include "med/printer.hpp"
#include "med/encoder_context.hpp"
#include "med/decoder_context.hpp"
#include "med/octet_encoder.hpp"
#include "med/octet_decoder.hpp"

#include "ut/ut.hpp"

struct msg_data_s
{
	char const* name;
	std::initializer_list<uint8_t> msg;

	friend std::ostream& operator << (std::ostream& o, msg_data_s const& d)
	{
		return o << d.name << " size=" << d.msg.size();
	}
};

struct Gtpu : testing::TestWithParam<msg_data_s>
{
};



TEST(decode, g_pdu)
{
	//sample G-PDU payload
	uint8_t const payload[] = {1,4,56,7,89,32,77,83,90,91};

	//contruct G-PDU directly in buffer
	uint8_t buf[sizeof(gtpu::header_s)+sizeof(payload)];
	auto ph = gtpu::header_s::from(buf);
	std::memcpy(ph->gpdu(1234, sizeof(payload)), payload, sizeof(payload));

	//now decode it with codec
	std::size_t alloc_buf[1024];
	med::allocator alloc{alloc_buf};
	med::decoder_context<med::allocator> ctx{buf, &alloc};
	gtpu::proto proto;
	decode(med::octet_decoder{ctx}, proto);

	gtpu::g_pdu const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	EXPECT_EQ(1, proto.header().version());
	EXPECT_TRUE(proto.header().is_gtpu());
	EXPECT_EQ(0, proto.header().sn());
	EXPECT_EQ(0, proto.header().npdu());
	EXPECT_EQ(1234, proto.header().get_teid());

	ASSERT_EQ(sizeof(payload), pmsg->size());
	ASSERT_TRUE(Matches(payload, pmsg->data(), pmsg->size()));
}

TEST(encode, g_pdu)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	uint32_t const teid = 0x04030201;
	proto.header().set_teid(teid);
	gtpu::g_pdu& msg = proto.select();

	uint8_t const pdu[] = {1,2,3,4,5};
	msg.set(sizeof(pdu), pdu);

	{
		encode(med::octet_encoder{ctx}, proto);
		uint8_t const encoded[] = {
			0x30, //version,flags(-)
			0xFF, //message type
			0,5, //length
			4,3,2,1, //teid
			1,2,3,4,5 //G-PDU
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));

		//check encoded with codec is properly peek-previewed with header_s
		auto ph = gtpu::header_s::from(encoded);
		EXPECT_EQ(teid, ph->teid());
		auto payload = ph->gpdu();
		ASSERT_FALSE(payload.empty());
		EXPECT_EQ(sizeof(pdu), ph->length());
		EXPECT_TRUE(Matches(pdu, payload.ro, sizeof(pdu)));
	}
}

//only as example how to fill out
TEST(encode, DISABLED_eh_chain)
{
	gtpu::proto proto;

	std::size_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	proto.ref<gtpu::end_marker>(); //just select, nothing to fill in msg
	proto.header().set_teid(0);
	proto.header().sn(1);

	auto& opt = proto.header().ref<gtpu::opt_header>();
	opt.ref<gtpu::ext::header>().ref<gtpu::ext::udp_port>().set(0x1234);

	auto& next = opt.ref<gtpu::ext::next_header>();
	auto* p = next.push_back();
	ASSERT_NE(nullptr, p);
	p->ref<gtpu::ext::pdcp_pdu>().set(0x8765);

	p = next.push_back();
	ASSERT_NE(nullptr, p);
	p->ref<gtpu::ext::long_pdcp_pdu>().set(0x38765);

	p = next.push_back();
	ASSERT_NE(nullptr, p);
	p->ref<gtpu::ext::sci>().set(0x37);

	p = next.push_back();
	ASSERT_NE(nullptr, p);
	auto& rc = p->ref<gtpu::ext::ran_container>();
	uint8_t const data[] = {1,2,3,4,5,6,7,8,9,10};
	rc.set(sizeof(data), data);

	//NOTE: need to explicitly terminate the chain
	p = next.push_back();
	ASSERT_NE(nullptr, p);
	p->ref<gtpu::ext::no_more>();

	encode(med::octet_encoder{ctx}, proto);
	{
		uint8_t const encoded[] = {
			0x36, //version,flags(E+S)
			0xFE, //message type
			0,36, //length
			0,0,0,0, //teid
			0,1, //sn (+S-flag)
			0, //npdu number
			0x40, //next eh = UDP port
			1, //4 octets
			0x12,0x34, //port
			0xC0, //next eh = PDCP PDU
			1, //4 octets
			0x87, 0x65,
			0x82, //next eh = long PDCP PDU
			2, //8 octets : ofs=20
			0x03, 0x87, 0x65,
			0,0,0, //spare
			0x20, //next eh = SCI
			1, //4 octets
			0x37,
			0, //spare
			0x81, //next eh = RAN container
			3, //12 octets
			1,2,3,4,5,6,7,8,9,10,
			0, // next eh = no_more
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, ctx.buffer().get_start()));
	}
}


TEST_P(Gtpu, codec)
{
	std::size_t alloc_buf[1024];
	med::allocator alloc{alloc_buf};

	gtpu::proto proto;

	auto& msg = GetParam().msg;
	{
		med::decoder_context<med::allocator> ctx{msg.begin(), msg.size(), &alloc};
		decode(med::octet_decoder{ctx}, proto);

		auto& opt_header = proto.header().ref<gtpu::opt_header>();
		if (!(proto.header().vf() & gtpu::version_flags::S))
		{
			opt_header.ref<gtpu::sequence_number>().clear();
		}
		if (!(proto.header().vf() & gtpu::version_flags::NP))
		{
			opt_header.ref<gtpu::npdu_number>().clear();
		}
		if (!(proto.header().vf() & gtpu::version_flags::E))
		{
			opt_header.ref<gtpu::ext::header>().clear();
		}
	}

	{
		uint8_t buffer[1024];
		med::encoder_context<> ctx{buffer};

		encode(med::octet_encoder{ctx}, proto);
		EXPECT_EQ(msg.size(), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(msg.begin(), buffer, msg.size()));
	}

}

msg_data_s const messages[] = {
	{"echo-request", { //0
		0x32, //version,flags(S)
		1, //message type
		0,12, //length
		0,0,0,0, //teid
		0,1, //sn (+S-flag)
		0, //npdu number
		0, //next eh type
		0xFF, //tag=private extension
		0,5, //length
		0,45, //extension id
		1,2,3 //extension value
	}},
	{"echo-response", { //1
		0x32, //version,flags(S)
		2, //message type
		0,6, //length
		0,0,0,0, //teid
		0,1, //sn (+S-flag)
		0, //npdu number
		0, //next eh type
		14, //tag=recovery
		45, //reset counter
	}},
	{"error-ind", { //2
		0x30, //version,flags(-)
		26, //message type
		0,12, //length
		0,0,0,0, //teid
		16, //tag=teid data
		1,2,3,4,
		133, //tag=peer address
		0,4, //len
		192,168,1,3, //IPv4
	}},
	{"supported-eh", { //3
		0x30, //version,flags(.)
		31, //message type
		0,5, //length
		0,0,0,0, //teid
		141, //tag=list
		3, //len
		1,3,7, //eh type(s)
	}},
	{"end-marker", { //4
		0x30, //version,flags(-)
		0xFE, //message type
		0,0, //length
		0,0,0,0, //teid
	}},
	{"gpdu", { //5
		0x30, //version,flags(-)
		0xFF, //message type
		0,5, //length
		4,3,2,1, //teid
		1,2,3,4,5 //G-PDU
	}},
	{"eh-chain", { //6
		0x36, //version,flags(E+S)
		0xFE, //message type = End Marker
		0,36, //length
		0,0,0,0, //teid
		0,1, //sn (+S-flag)
		0, //npdu number
		0x40, //next eh = UDP port
		1, //4 octets
		0x12,0x34, //port
		0xC0, //next eh = PDCP PDU
		1, //4 octets
		0x87, 0x65,
		0x82, //next eh = long PDCP PDU
		2, //8 octets
		0x03, 0x87, 0x65,
		0,0,0, //spare
		0x20, //next eh = SCI
		1, //4 octets
		0x37,
		0, //spare
		0x81, //next eh = RAN container
		3, //12 octets
		1,2,3,4,5,6,7,8,9,10,
		0, // next eh = no_more
	 }},
	{"eh-chain-any", { //7
		0x36, //version,flags(E+S)
		0xFE, //message type
		0,36, //length
		0,0,0,0, //teid
		0,1, //sn (+S-flag)
		0, //npdu number
		0x40, //next eh = UDP port
		1, //4 octets
		0x12,0x34, //port
		0xC0, //next eh = PDCP PDU
		1, //4 octets
		0x87, 0x65,
		0x82, //next eh = long PDCP PDU
		2, //8 octets
		0x03, 0x87, 0x65,
		0,0,0, //spare
		0x20, //next eh = SCI
		1, //4 octets
		0x37,
		0, //spare
		0x87, //next eh = unknown container
		3, //12 octets
		1,2,3,4,5,6,7,8,9,10,
		0, // next eh = no_more
	 }},
};

INSTANTIATE_TEST_SUITE_P(Suite, Gtpu, testing::ValuesIn(messages));

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
