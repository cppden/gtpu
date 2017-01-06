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

TEST(decode, echo_request)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	uint8_t const encoded[] = {
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
	};
	ctx.reset(encoded, sizeof(encoded));
	if (!decode(med::make_octet_decoder(ctx), proto))
	{
//		dummy_sink d{2};
//		med::print(d, proto);
		FAIL() << toString(ctx.error_ctx());
	}

	gtpu::echo_request const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	ASSERT_EQ(1, proto.header().version());
	ASSERT_EQ(1, pmsg->count<gtpu::private_extension>());
	for (auto const& pe : pmsg->get<gtpu::private_extension>())
	{
		EXPECT_EQ(pe.get<gtpu::extension_id>().get(), 45);
	}
}

TEST(encode, echo_request)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	gtpu::echo_request& msg = proto.select();
	proto.header().sn(1);
	proto.header().set_teid(0);

	gtpu::private_extension* pe = msg.push_back<gtpu::private_extension>();
	ASSERT_NE(nullptr, pe);
	pe->ref<gtpu::extension_id>().set(45);
	uint8_t const ev[] = {0x01,0x02,0x03};
	pe->ref<gtpu::extension_value>().set(sizeof(ev), ev);

	{
		//static_assert(med::has_ie_type_v<gtpu::proto>,"");
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
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
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));
	}
}


TEST(decode, echo_response)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	uint8_t const encoded[] = {
		0x32, //version,flags(S)
		2, //message type
		0,6, //length
		0,0,0,0, //teid
		0,1, //sn (+S-flag)
		0, //npdu number
		0, //next eh type
		14, //tag=recovery
		45, //reset counter
	};
	ctx.reset(encoded, sizeof(encoded));
	if (!decode(med::make_octet_decoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }

	gtpu::echo_response const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	ASSERT_EQ(1, proto.header().version());

	gtpu::recovery const& rec = pmsg->field();
	EXPECT_EQ(rec.get(), 45);
}

TEST(encode, echo_response)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	gtpu::echo_response& msg = proto.select();
	proto.header().sn(1);
	proto.header().set_teid(0);

	msg.ref<gtpu::recovery>().set(45);

	{
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
			0x32, //version,flags(S)
			2, //message type
			0,6, //length
			0,0,0,0, //teid
			0,1, //sn (+S-flag)
			0, //npdu number
			0, //next eh type
			14, //tag=recovery
			45, //reset counter
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));
	}
}


TEST(decode, error_indication)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	uint8_t const encoded[] = {
		0x30, //version,flags(-)
		26, //message type
		0,12, //length
		0,0,0,0, //teid
		16, //tag=teid data
		1,2,3,4,
		133, //tag=peer address
		0,4, //len
		192,168,1,3, //IPv4
	};
	ctx.reset(encoded, sizeof(encoded));
	if (!decode(med::make_octet_decoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }

	gtpu::error_indication const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	ASSERT_EQ(1, proto.header().version());
	ASSERT_TRUE(proto.header().is_gtpu());

	EXPECT_EQ(0x01020304, pmsg->get<gtpu::teid_data>().get());

	gtpu::peer_address const& rf = pmsg->field();
	ASSERT_EQ(rf.size(), 4);
}

TEST(encode, error_indication)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	gtpu::error_indication& msg = proto.select();
	proto.header().set_teid(0);

	msg.ref<gtpu::teid_data>().set(0x01020304);
	uint8_t const ip[] = {192,168,1,3};
	msg.ref<gtpu::peer_address>().set(4, ip);

	{
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
			0x30, //version,flags(-)
			26, //message type
			0,12, //length
			0,0,0,0, //teid
			16, //tag=teid data
			1,2,3,4,
			133, //tag=peer address
			0,4, //len
			192,168,1,3, //IPv4
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));
	}
}


TEST(decode, supported_eh)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	uint8_t const encoded[] = {
		0x30, //version,flags(.)
		31, //message type
		0,5, //length
		0,0,0,0, //teid
		141, //tag=list
		3, //len
		1,3,7, //eh type(s)
	};
	ctx.reset(encoded, sizeof(encoded));
	if (!decode(med::make_octet_decoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }

	gtpu::supported_eh const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	ASSERT_EQ(1, proto.header().version());

	//ASSERT_EQ(3, pmsg->get<gtpu::ext_hdr_type_list>().count<gtpu::ext::header_type>());
	check_seqof<gtpu::ext::header_type>(pmsg->get<gtpu::eh_type_list>(), {1,3,7});
}

TEST(encode, supported_eh)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	gtpu::supported_eh& msg = proto.select();
	proto.header().set_teid(0);

	auto& tl = msg.ref<gtpu::eh_type_list>();
	tl.push_back<gtpu::ext::header_type>(ctx)->set(1);
	tl.push_back<gtpu::ext::header_type>(ctx)->set(3);
	tl.push_back<gtpu::ext::header_type>(ctx)->set(7);

	{
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
			0x30, //version,flags(.)
			31, //message type
			0,5, //length
			0,0,0,0, //teid
			141, //tag=list
			3, //len
			1,3,7, //eh type(s)
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));
	}
}


TEST(decode, end_marker)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	uint8_t const encoded[] = {
		0x30, //version,flags(-)
		0xFE, //message type
		0,0, //length
		0,0,0,0, //teid
	};
	ctx.reset(encoded, sizeof(encoded));
	if (!decode(med::make_octet_decoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }

	gtpu::end_marker const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	ASSERT_EQ(1, proto.header().version());
	ASSERT_TRUE(proto.header().is_gtpu());

	ASSERT_EQ(0, pmsg->count<gtpu::private_extension>());
}

TEST(encode, end_marker)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	proto.ref<gtpu::end_marker>();
	proto.header().set_teid(0);

	{
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
			0x30, //version,flags(-)
			0xFE, //message type
			0,0, //length
			0,0,0,0, //teid
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));
	}
}


TEST(decode, g_pdu)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	//sample G-PDU payload
	uint8_t const payload[] = {1,4,56,7,89,32,77,83,90,91};

	//contruct G-PDU directly in buffer
	uint8_t buf[sizeof(gtpu::header_s)+sizeof(payload)];
	auto ph = gtpu::header_s::from(buf);
	std::memcpy(ph->gpdu(1234, sizeof(payload)), payload, sizeof(payload));

	//now decode it with codec
	ctx.reset(buf, sizeof(buf));
	if (!decode(med::make_octet_decoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }

	gtpu::g_pdu const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);

	EXPECT_EQ(1, proto.header().version());
	EXPECT_TRUE(proto.header().is_gtpu());
	EXPECT_EQ(0, proto.header().sn());
	EXPECT_EQ(0, proto.header().npdu());
	//EXPECT_TRUE(proto.header().is_short());
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
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
			0x30, //version,flags(-)
			0xFF, //message type
			0,5, //length
			4,3,2,1, //teid
			1,2,3,4,5
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));

		//check encoded with codec is properly peek-previewed with header_s
		auto ph = gtpu::header_s::from(encoded);
		EXPECT_EQ(teid, ph->teid());
		auto payload = ph->gpdu();
		ASSERT_NE(nullptr, payload);
		EXPECT_EQ(sizeof(pdu), ph->length());
		EXPECT_TRUE(Matches(pdu, payload, sizeof(pdu)));
	}
}


TEST(decode, eh_chain)
{
	gtpu::proto proto;
	med::decoder_context<> ctx;
	std::size_t alloc_buf[1024];
	ctx.get_allocator().reset(alloc_buf);

	uint8_t const encoded[] = {
		0x36, //version,flags(E+S)
		0xFE, //message type
		0,8, //length
		0,0,0,0, //teid
		0,1, //sn (+S-flag)
		0, //npdu number
		0x40, //next eh = UDP port
		1, //4 octets
		0x12,0x34, //port
		0, // next eh = no_more
	};
	ctx.reset(encoded, sizeof(encoded));
	if (!decode(med::make_octet_decoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }

	gtpu::end_marker const* pmsg = proto.cselect();
	ASSERT_NE(nullptr, pmsg);
	EXPECT_EQ(0, pmsg->count<gtpu::private_extension>());

	ASSERT_EQ(1, proto.header().version());
	ASSERT_TRUE(proto.header().is_gtpu());

	gtpu::ext::header const* eh = proto.header().field();
	ASSERT_NE(nullptr, eh);
}

#if 0
TEST(encode, end_marker)
{
	gtpu::proto proto;
	uint8_t buffer[1024];
	med::encoder_context<> ctx{buffer};

	proto.ref<gtpu::end_marker>();
	proto.header().set_teid(0);

	{
		if (!encode(med::make_octet_encoder(ctx), proto)) { FAIL() << toString(ctx.error_ctx()); }
		uint8_t const encoded[] = {
			0x30, //version,flags(-)
			0xFE, //message type
			0,0, //length
			0,0,0,0, //teid
		};

		EXPECT_EQ(sizeof(encoded), ctx.buffer().get_offset());
		EXPECT_TRUE(Matches(encoded, buffer));
	}
}
#endif

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
