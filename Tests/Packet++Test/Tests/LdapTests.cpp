#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "LdapLayer.h"

PTF_TEST_CASE(LdapParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// LDAP controls
	{
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_controls.dat", pcpp::LINKTYPE_LINUX_SLL);
		pcpp::Packet ldapWithControlsPacket(&rawPacket1);

		auto ldapLayer = ldapWithControlsPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(ldapLayer);

		auto controls = ldapLayer->getControls();
		std::vector<pcpp::LdapControl> expectedControls = {
			{"1.2.840.113556.1.4.801", "3003020107"},
			{"1.2.840.113556.1.4.319", "3006020201f40400"}
		};
		PTF_ASSERT_VECTORS_EQUAL(controls, expectedControls);
	}

	// LDAP controls 2
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		pcpp::Packet ldapWithControlsPacket(&rawPacket1);

		auto ldapLayer = ldapWithControlsPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(ldapLayer);

		auto controls = ldapLayer->getControls();
		std::vector<pcpp::LdapControl> expectedControls = {{"1.3.6.1.4.1.42.2.27.8.5.1"}};
		PTF_ASSERT_VECTORS_EQUAL(controls, expectedControls);
	}

	// BindRequest with simple authentication
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		pcpp::Packet bindRequestPacket(&rawPacket1);

		auto bindRequestLayer = bindRequestPacket.getLayerOfType<pcpp::LdapBindRequestLayer>();
		PTF_ASSERT_NOT_NULL(bindRequestLayer);
		PTF_ASSERT_EQUAL(bindRequestLayer->getMessageID(), 2);
		PTF_ASSERT_EQUAL(bindRequestLayer->getLdapOperationType(), pcpp::LdapOperationType::BindRequest, enum);
		PTF_ASSERT_EQUAL(bindRequestLayer->getVersion(), 3);
		PTF_ASSERT_EQUAL(bindRequestLayer->getName(), "cn=Administrator,cn=Users,dc=cloudshark-a,dc=example,dc=com");
		PTF_ASSERT_EQUAL(bindRequestLayer->getAuthenticationType(), pcpp::LdapBindRequestLayer::AuthenticationType::Simple, enumclass);
		PTF_ASSERT_EQUAL(bindRequestLayer->getSimpleAuthentication(), "cloudshark123!");
		PTF_ASSERT_RAISES(bindRequestLayer->getSaslAuthentication(), std::invalid_argument, "Authentication type is not sasl");
	}

	// BindRequest with SASL authentication
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request2.dat");
		pcpp::Packet bindRequestPacket(&rawPacket1);

		auto bindRequestLayer = bindRequestPacket.getLayerOfType<pcpp::LdapBindRequestLayer>();
		PTF_ASSERT_NOT_NULL(bindRequestLayer);
		PTF_ASSERT_EQUAL(bindRequestLayer->getMessageID(), 7);
		PTF_ASSERT_EQUAL(bindRequestLayer->getLdapOperationType(), pcpp::LdapOperationType::BindRequest, enum);
		PTF_ASSERT_EQUAL(bindRequestLayer->getVersion(), 3);
		PTF_ASSERT_EQUAL(bindRequestLayer->getName(), "");
		PTF_ASSERT_EQUAL(bindRequestLayer->getAuthenticationType(), pcpp::LdapBindRequestLayer::AuthenticationType::Sasl, enumclass);
		PTF_ASSERT_RAISES(bindRequestLayer->getSimpleAuthentication(), std::invalid_argument, "Authentication type is not simple");
		auto saslAuth = bindRequestLayer->getSaslAuthentication();
		PTF_ASSERT_EQUAL(saslAuth.mechanism, "GSS-SPNEGO");
		PTF_ASSERT_EQUAL(saslAuth.credentials, "6082051a06062b0601050502a082050e3082050aa024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa28204e0048204dc608204d806092a864886f71201020201006e8204c7308204c3a003020105a10302010ea20703050020000000a38203e0618203dc308203d8a003020105a1151b1357324b332e564d4e4554312e564d2e42415345a22f302da003020102a12630241b046c6461701b1c77326b332d3130312e77326b332e766d6e6574312e766d2e62617365a382038730820383a003020117a103020107a2820375048203716a61c886ba58d162113db4268f7743a17eb476183bc0c519addea76556a3701de34903e6bd3f3fdca0b01bbccb9a8693b23fa8d1985e14922e4ca19b05a90769845a5858515bba4af2d7e59bfa8634285a2e954fb518378b8d3f2744b9bbf8842b4807879ff28e55bfba4967e8c1d3b6c4e358a561c54abbc1cb7c97b6503fe59b7fee6423dffe66fe6dcb8af00e69c53d6b576f5506990438310fb7dd1468a32fd8e0deab40b15ecfd438568370140a1edafee701a4a4b4e7b3aaefdc4b1aff5868aefe5a36294d5dd687d5a6493143d3ade8031c98d28f6c7f3dcea41435132f675f26940d1f69e573e5ece6ed5a66111ff9f4b02a8ddd19086e5b9dc0adc86a0bc1230f1b715ffc4004dfc4a7d5f78a4dc31abf830ae6e3bfd21c87fa5196549e130f6a081bafcf4170ae201c78a3829a01dba578a2ef968f2ab6668d8114dfcc65d7038f5558be7cdd9246d52247915260a40e59c48b08a1ed61427fd303917c6b34b701a4ba9a3815d4828a228cd209da137626e2029aabf6c200bf7fd63cf6d43bb618b31ac48e09613589d74a69542e909ce0dc9c57c77f7d89b966de200053a58ea58f2374513961638a30ca49ef0eec679d927e385b5da7d4d3c1a59169b4630b874a1d969e45d1fe3782089f4385024955093b308e1964d307915271aa886c3d9b64d846c88ca1341fd2f72b76679d4f258f647bc04820e42776c9ec0d01464652763a49d822c9d25b603903ebd6338952259b83a740a420d69d23aebbdf06a92d88a46ffcd8d81a47b6ec99b6cea0489cc83ef15757c4053d538446f2e6b9eba12ce4969b8d6df9b3ef574b7d401341c2f555a00f029164e5d387282c0c8791ba8c69816248e2e544a9c12b7aeba629fdeea2e111655e44b9c215924c5455eaa4ab32aea1d9cef1d86e8acf6b0ff4dcabaf4f0e2d9ae65c8bb1065e0418ff12d4626930315938bfe00a8d03e8e70e9dea9dc9ff74854cbb4dbdf700a62e77b26e50b13e2d3960c913360c84c87e801ed3df3db0e27604508cb730c5a052c068abe5826b01be9f62e33b9af8edb6667c57cb1aa879743b77a7432f75fe3ae211f96af41adef1e1c507256fe5fa2bccabe52cf8216d3410e6378506d427343458332d153a77a162c4c5f18d9f31b0c142880cad2229981720615ab26b7c13442e43178aadee436510c91bc9d5d735eb9453cf39cef5120e28603775f0483f01c3c48b5b060ca7f3a54d7c7c99a481c93081c6a003020117a281be0481bb03ab656760a3512fecc7032da8b2014659f0fb34eb76b461e4044da24d16d458e3e1c58919c74c4c0720aafb87a948152372a2483a4d1ae9b95b858a52abaa94e7aa641a8b997d7e6c6e570b5908cc549155f5e6f110c98d648978727abae3921da52a4c1fd76beb121bf3396be8f98e4acf1ebfc3b6fb7a1354c121873e59185db90030084d97864798d79eb9df30756ca1faa7a80880f74f7d93642d9ceb5e0128ced6ab096a4f015e5a032b4270231e7ff1bcd087e8b527027d");
	}

	// SearchRequest
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
		pcpp::Packet searchRequestPacket(&rawPacket1);

		auto searchRequestLayer = searchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(searchRequestLayer);
		PTF_ASSERT_EQUAL(searchRequestLayer->getMessageID(), 9);
		PTF_ASSERT_EQUAL(searchRequestLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchRequest, enum);
		PTF_ASSERT_EQUAL(searchRequestLayer->getBaseObject(), "cn=schema");
		PTF_ASSERT_EQUAL(searchRequestLayer->getScope(), pcpp::LdapSearchRequestLayer::SearchRequestScope::BaseObject, enum);
		PTF_ASSERT_EQUAL(searchRequestLayer->getDerefAlias(), pcpp::LdapSearchRequestLayer::DerefAliases::DerefAlways, enum);
		PTF_ASSERT_EQUAL(searchRequestLayer->getSizeLimit(), 0);
		PTF_ASSERT_EQUAL(searchRequestLayer->getTimeLimit(), 0);
		PTF_ASSERT_FALSE(searchRequestLayer->getTypesOnly());
		PTF_ASSERT_EQUAL(searchRequestLayer->toString(), "LDAP Layer, SearchRequest, \"cn=schema\", BaseObject");
		auto attributes = searchRequestLayer->getAttributes();
		std::vector<std::string> expectedAttributes = {
			"objectClasses",
			"attributeTypes",
			"ldapSyntaxes",
			"matchingRules",
			"matchingRuleUse",
			"dITContentRules",
			"dITStructureRules",
			"nameForms",
			"createTimestamp",
			"modifyTimestamp",
			"*",
			"+"
		};
		PTF_ASSERT_VECTORS_EQUAL(attributes, expectedAttributes);
	}

	// SearchResultEntry
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_res_entry.dat");
		pcpp::Packet searchResEntryPacket(&rawPacket1);

		auto searchResultEntryLayer = searchResEntryPacket.getLayerOfType<pcpp::LdapSearchResultEntryLayer>();
		PTF_ASSERT_NOT_NULL(searchResultEntryLayer);
		PTF_ASSERT_EQUAL(searchResultEntryLayer->getMessageID(), 16);
		PTF_ASSERT_EQUAL(searchResultEntryLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultEntry, enum);
		PTF_ASSERT_EQUAL(searchResultEntryLayer->getObjectName(), "cn=b.smith,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org");
		std::vector<pcpp::LdapPartialAttribute> expectedPartialAttributes = {
			{"objectclass", {"inetOrgPerson", "organizationalPerson", "person", "top"}},
			{"sn",          {"Young"}},
			{"cn",          {"b.smith"}},
			{"givenname",   {"Beatrix"}}
		};
		PTF_ASSERT_VECTORS_EQUAL(searchResultEntryLayer->getAttributes(), expectedPartialAttributes);
	}

	// SearchResultDone
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_res_done.dat");
		pcpp::Packet searchReusltDonePacket(&rawPacket1);

		auto searchResultDoneLayer = searchReusltDonePacket.getLayerOfType<pcpp::LdapSearchResultDoneLayer>();
		PTF_ASSERT_NOT_NULL(searchResultDoneLayer);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getMessageID(), 25);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getResultCode(), pcpp::LdapResultCode::Success);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getDiagnosticMessage(), "");
	}

	// ModifyResponse
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_modify_response.dat");
		pcpp::Packet modifyResponsePacket(&rawPacket1);

		auto modifyResponseLayer = modifyResponsePacket.getLayerOfType<pcpp::LdapModifyResponseLayer>();
		PTF_ASSERT_NOT_NULL(modifyResponseLayer);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getMessageID(), 19);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getResultCode(), pcpp::LdapResultCode::Success);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(modifyResponseLayer->getDiagnosticMessage(), "");
	}

	// AddResponse
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_add_response.dat");
		pcpp::Packet addResponsePacket(&rawPacket1);

		auto addResponseLayer = addResponsePacket.getLayerOfType<pcpp::LdapAddResponseLayer>();
		PTF_ASSERT_NOT_NULL(addResponseLayer);
		PTF_ASSERT_EQUAL(addResponseLayer->getMessageID(), 27);
		PTF_ASSERT_EQUAL(addResponseLayer->getResultCode(), pcpp::LdapResultCode::Success);
		PTF_ASSERT_EQUAL(addResponseLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(addResponseLayer->getDiagnosticMessage(), "");
	}

	// DeleteResponse
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_del_response.dat");
		pcpp::Packet deleteResponsePacket(&rawPacket1);

		auto deleteResponseLayer = deleteResponsePacket.getLayerOfType<pcpp::LdapDeleteResponseLayer>();
		PTF_ASSERT_NOT_NULL(deleteResponseLayer);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getMessageID(), 22);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getResultCode(), pcpp::LdapResultCode::Success);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(deleteResponseLayer->getDiagnosticMessage(), "");
	}

	// Test tryGet LdapLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		buffer1[68] = 0x04;
		pcpp::Packet malformedLdapPacket(&rawPacket1);
		auto malformedLdapLayer = malformedLdapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(malformedLdapLayer);
		uint16_t messageId;
		PTF_ASSERT_FALSE(malformedLdapLayer->tryGet(&pcpp::LdapLayer::getMessageID, messageId));
		std::vector<pcpp::LdapControl> controls;
		PTF_ASSERT_TRUE(malformedLdapLayer->tryGet(&pcpp::LdapLayer::getControls, controls));
		std::vector<pcpp::LdapControl> expectedControls = {{"1.3.6.1.4.1.42.2.27.8.5.1"}};
		PTF_ASSERT_VECTORS_EQUAL(controls, expectedControls);
	}

	// Test tryGet LdapSearchRequestLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
		buffer1[127] = 0x31;
		pcpp::Packet malformedSearchRequestPacket(&rawPacket1);
		auto malformedSearchRequestLayer = malformedSearchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(malformedSearchRequestLayer);
		uint16_t messageId;
		PTF_ASSERT_TRUE(malformedSearchRequestLayer->tryGet(&pcpp::LdapSearchRequestLayer::getMessageID, messageId));
		PTF_ASSERT_EQUAL(messageId, 9);
		std::vector<std::string> attrs;
		PTF_ASSERT_FALSE(malformedSearchRequestLayer->tryGet(&pcpp::LdapSearchRequestLayer::getAttributes, attrs));
	}

	// Negative tests

	// Unknown LDAP operation type (30)
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
		buffer1[72] = 0x7e;
		pcpp::Packet unknownLdapOperationTypePacket(&rawPacket1);
		PTF_ASSERT_NULL(unknownLdapOperationTypePacket.getLayerOfType<pcpp::LdapSearchRequestLayer>());
		PTF_ASSERT_NULL(unknownLdapOperationTypePacket.getLayerOfType<pcpp::LdapLayer>());
	}

	// Root record isn't an ASN.1 sequence (but a set)
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
		buffer1[66] = 0x31;
		pcpp::Packet unexpectedRootAsn1RecordPacket(&rawPacket1);
		PTF_ASSERT_NULL(unexpectedRootAsn1RecordPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>());
		PTF_ASSERT_NULL(unexpectedRootAsn1RecordPacket.getLayerOfType<pcpp::LdapLayer>());
	}

	// Bad ASN.1 data
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
		buffer1[68] = 0x01;
		pcpp::Packet badAsn1Packet(&rawPacket1);
		PTF_ASSERT_NULL(badAsn1Packet.getLayerOfType<pcpp::LdapSearchRequestLayer>());
		PTF_ASSERT_NULL(badAsn1Packet.getLayerOfType<pcpp::LdapLayer>());
	}
} // LdapParsingTest

PTF_TEST_CASE(LdapCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// BindRequest with simple authentication
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		pcpp::Packet bindRequestPacket(&rawPacket1);

		pcpp::LdapBindRequestLayer bindRequestLayer(
			2, 3, "cn=Administrator,cn=Users,dc=cloudshark-a,dc=example,dc=com", "cloudshark123!", {{"1.3.6.1.4.1.42.2.27.8.5.1"}});

		auto expectedBindRequestLayer = bindRequestPacket.getLayerOfType<pcpp::LdapBindRequestLayer>();
		PTF_ASSERT_NOT_NULL(expectedBindRequestLayer);

		PTF_ASSERT_BUF_COMPARE(bindRequestLayer.getData(), expectedBindRequestLayer->getData(),
		                       expectedBindRequestLayer->getDataLen());
	}

	// BindRequest with SASL authentication
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request2.dat");
		pcpp::Packet bindRequestPacket(&rawPacket1);

		pcpp::LdapBindRequestLayer::SaslAuthentication saslAuth = {"GSS-SPNEGO", "6082051a06062b0601050502a082050e3082050aa024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa28204e0048204dc608204d806092a864886f71201020201006e8204c7308204c3a003020105a10302010ea20703050020000000a38203e0618203dc308203d8a003020105a1151b1357324b332e564d4e4554312e564d2e42415345a22f302da003020102a12630241b046c6461701b1c77326b332d3130312e77326b332e766d6e6574312e766d2e62617365a382038730820383a003020117a103020107a2820375048203716a61c886ba58d162113db4268f7743a17eb476183bc0c519addea76556a3701de34903e6bd3f3fdca0b01bbccb9a8693b23fa8d1985e14922e4ca19b05a90769845a5858515bba4af2d7e59bfa8634285a2e954fb518378b8d3f2744b9bbf8842b4807879ff28e55bfba4967e8c1d3b6c4e358a561c54abbc1cb7c97b6503fe59b7fee6423dffe66fe6dcb8af00e69c53d6b576f5506990438310fb7dd1468a32fd8e0deab40b15ecfd438568370140a1edafee701a4a4b4e7b3aaefdc4b1aff5868aefe5a36294d5dd687d5a6493143d3ade8031c98d28f6c7f3dcea41435132f675f26940d1f69e573e5ece6ed5a66111ff9f4b02a8ddd19086e5b9dc0adc86a0bc1230f1b715ffc4004dfc4a7d5f78a4dc31abf830ae6e3bfd21c87fa5196549e130f6a081bafcf4170ae201c78a3829a01dba578a2ef968f2ab6668d8114dfcc65d7038f5558be7cdd9246d52247915260a40e59c48b08a1ed61427fd303917c6b34b701a4ba9a3815d4828a228cd209da137626e2029aabf6c200bf7fd63cf6d43bb618b31ac48e09613589d74a69542e909ce0dc9c57c77f7d89b966de200053a58ea58f2374513961638a30ca49ef0eec679d927e385b5da7d4d3c1a59169b4630b874a1d969e45d1fe3782089f4385024955093b308e1964d307915271aa886c3d9b64d846c88ca1341fd2f72b76679d4f258f647bc04820e42776c9ec0d01464652763a49d822c9d25b603903ebd6338952259b83a740a420d69d23aebbdf06a92d88a46ffcd8d81a47b6ec99b6cea0489cc83ef15757c4053d538446f2e6b9eba12ce4969b8d6df9b3ef574b7d401341c2f555a00f029164e5d387282c0c8791ba8c69816248e2e544a9c12b7aeba629fdeea2e111655e44b9c215924c5455eaa4ab32aea1d9cef1d86e8acf6b0ff4dcabaf4f0e2d9ae65c8bb1065e0418ff12d4626930315938bfe00a8d03e8e70e9dea9dc9ff74854cbb4dbdf700a62e77b26e50b13e2d3960c913360c84c87e801ed3df3db0e27604508cb730c5a052c068abe5826b01be9f62e33b9af8edb6667c57cb1aa879743b77a7432f75fe3ae211f96af41adef1e1c507256fe5fa2bccabe52cf8216d3410e6378506d427343458332d153a77a162c4c5f18d9f31b0c142880cad2229981720615ab26b7c13442e43178aadee436510c91bc9d5d735eb9453cf39cef5120e28603775f0483f01c3c48b5b060ca7f3a54d7c7c99a481c93081c6a003020117a281be0481bb03ab656760a3512fecc7032da8b2014659f0fb34eb76b461e4044da24d16d458e3e1c58919c74c4c0720aafb87a948152372a2483a4d1ae9b95b858a52abaa94e7aa641a8b997d7e6c6e570b5908cc549155f5e6f110c98d648978727abae3921da52a4c1fd76beb121bf3396be8f98e4acf1ebfc3b6fb7a1354c121873e59185db90030084d97864798d79eb9df30756ca1faa7a80880f74f7d93642d9ceb5e0128ced6ab096a4f015e5a032b4270231e7ff1bcd087e8b527027d"};

		pcpp::LdapBindRequestLayer bindRequestLayer(215, 3, "", saslAuth);

		auto expectedBindRequestLayer = bindRequestPacket.getLayerOfType<pcpp::LdapBindRequestLayer>();
		PTF_ASSERT_NOT_NULL(expectedBindRequestLayer);

//		PTF_ASSERT_BUF_COMPARE(bindRequestLayer.getData(), expectedBindRequestLayer->getData(),
//		                       expectedBindRequestLayer->getDataLen());
	}

	// SearchRequest
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
		pcpp::Packet searchRequestPacket(&rawPacket1);

		std::vector<uint8_t> filterBytes = {
			0xa3, 0x18, 0x04, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x04, 0x09,
			0x73, 0x75, 0x62, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61
		};
		std::vector<std::string> attributes = {
			"objectClasses",
			"attributeTypes",
			"ldapSyntaxes",
			"matchingRules",
			"matchingRuleUse",
			"dITContentRules",
			"dITStructureRules",
			"nameForms",
			"createTimestamp",
			"modifyTimestamp",
			"*",
			"+"
		};
		pcpp::LdapSearchRequestLayer searchRequestLayer(
			9, "cn=schema", pcpp::LdapSearchRequestLayer::SearchRequestScope::BaseObject,
			pcpp::LdapSearchRequestLayer::DerefAliases::DerefAlways,
			0, 0, false, filterBytes, attributes);

		auto expectedSearchRequestLayer = searchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchRequestLayer);

		PTF_ASSERT_BUF_COMPARE(searchRequestLayer.getData(), expectedSearchRequestLayer->getData(),
		                       expectedSearchRequestLayer->getDataLen());
	}

	// SearchRequest with Controls
	{
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_controls.dat", pcpp::LINKTYPE_LINUX_SLL);
		pcpp::Packet searchRequestPacket(&rawPacket1);

		std::vector<uint8_t> filterBytes = {
			0xa9, 0x39, 0x81, 0x1c, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x2e, 0x31,
			0x31, 0x33, 0x37, 0x33, 0x30, 0x2e, 0x33, 0x2e, 0x33, 0x2e, 0x32, 0x2e, 0x34, 0x36, 0x2e, 0x31,
			0x82, 0x10, 0x64, 0x65, 0x70, 0x61, 0x72, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x62,
			0x65, 0x72, 0x83, 0x07, 0x3e, 0x3d, 0x4e, 0x34, 0x37, 0x30, 0x39
		};
		std::vector<std::string> attributes = {"*", "ntsecuritydescriptor"};
		std::vector<pcpp::LdapControl> controls = {
			{"1.2.840.113556.1.4.801", "3003020107"},
			{"1.2.840.113556.1.4.319", "3006020201f40400"}
		};

		pcpp::LdapSearchRequestLayer searchRequestLayer(
			6, "DC=matrix,DC=local", pcpp::LdapSearchRequestLayer::SearchRequestScope::WholeSubtree,
			pcpp::LdapSearchRequestLayer::DerefAliases::DerefAlways,
			0, 0, false, filterBytes, attributes, controls);

		auto expectedSearchRequestLayer = searchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchRequestLayer);

		PTF_ASSERT_BUF_COMPARE(searchRequestLayer.getData(), expectedSearchRequestLayer->getData(),
		                       expectedSearchRequestLayer->getDataLen());
	}

	// Generic LDAP packet with Controls
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		pcpp::Packet ldapPacket(&rawPacket1);

		pcpp::Asn1IntegerRecord integerRecord(3);
		pcpp::Asn1OctetStringRecord stringRecord("cn=Administrator,cn=Users,dc=cloudshark-a,dc=example,dc=com");
		uint8_t contextSpecificData[14] = {0x63, 0x6c, 0x6f, 0x75, 0x64, 0x73, 0x68, 0x61, 0x72, 0x6b, 0x31, 0x32, 0x33, 0x21};
		pcpp::Asn1GenericRecord contextSpecificRecord(pcpp::Asn1TagClass::ContextSpecific, false, 0, contextSpecificData, 14);
		std::vector<pcpp::LdapControl> controls = {{"1.3.6.1.4.1.42.2.27.8.5.1"}};

		pcpp::LdapLayer ldapLayer(2, pcpp::LdapOperationType::BindRequest, {&integerRecord, &stringRecord, &contextSpecificRecord}, controls);

		auto expectedLdapLayer = ldapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(expectedLdapLayer);

		PTF_ASSERT_BUF_COMPARE(ldapLayer.getData(), expectedLdapLayer->getData(),
		                       expectedLdapLayer->getDataLen());

	}

	// SearchResultEntry
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_res_entry.dat");
		pcpp::Packet searchResultEntryPacket(&rawPacket1);

		std::vector<pcpp::LdapPartialAttribute> partialAttributes = {
			{"objectclass", {"inetOrgPerson", "organizationalPerson", "person", "top"}},
			{"sn",          {"Young"}},
			{"cn",          {"b.smith"}},
			{"givenname",   {"Beatrix"}}
		};

		pcpp::LdapSearchResultEntryLayer searchResultEntryLayer(16, "cn=b.smith,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org", partialAttributes);

		auto expectedSearchResultEntryLayer = searchResultEntryPacket.getLayerOfType<pcpp::LdapSearchResultEntryLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchResultEntryLayer);

		PTF_ASSERT_BUF_COMPARE(searchResultEntryLayer.getData(), expectedSearchResultEntryLayer->getData(),
		                       expectedSearchResultEntryLayer->getDataLen());
	}

	// SearchResultDone
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_res_done.dat");
		pcpp::Packet searchResultDonePacket(&rawPacket1);

		pcpp::LdapSearchResultDoneLayer searchResultDoneLayer(25, pcpp::LdapResultCode::Success, "", "");

		auto expectedSearchResultDoneLayer = searchResultDonePacket.getLayerOfType<pcpp::LdapSearchResultDoneLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchResultDoneLayer);

		PTF_ASSERT_BUF_COMPARE(searchResultDoneLayer.getData(), expectedSearchResultDoneLayer->getData(),
		                       expectedSearchResultDoneLayer->getDataLen());
	}

	// ModifyResponse
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_modify_response.dat");
		pcpp::Packet modifyResponsePacket(&rawPacket1);

		pcpp::LdapModifyResponseLayer modifyResponseLayer(19, pcpp::LdapResultCode::Success, "", "");

		auto expectedModifyResponseLayer = modifyResponsePacket.getLayerOfType<pcpp::LdapModifyResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedModifyResponseLayer);

		PTF_ASSERT_BUF_COMPARE(modifyResponseLayer.getData(), expectedModifyResponseLayer->getData(),
		                       expectedModifyResponseLayer->getDataLen());
	}

	// AddResponse
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_add_response.dat");
		pcpp::Packet addResponsePacket(&rawPacket1);

		pcpp::LdapAddResponseLayer addResponseLayer(27, pcpp::LdapResultCode::Success, "", "");

		auto expectedAddResponseLayer = addResponsePacket.getLayerOfType<pcpp::LdapAddResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedAddResponseLayer);

		PTF_ASSERT_BUF_COMPARE(addResponseLayer.getData(), expectedAddResponseLayer->getData(),
		                       expectedAddResponseLayer->getDataLen());
	}

	// DelResponse
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_del_response.dat");
		pcpp::Packet deleteResponsePacket(&rawPacket1);

		pcpp::LdapDeleteResponseLayer deleteResponseLayer(22, pcpp::LdapResultCode::Success, "", "");

		auto expectedDeleteResponseLayer = deleteResponsePacket.getLayerOfType<pcpp::LdapDeleteResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedDeleteResponseLayer);

		PTF_ASSERT_BUF_COMPARE(deleteResponseLayer.getData(), expectedDeleteResponseLayer->getData(),
		                       expectedDeleteResponseLayer->getDataLen());
	}
} // LdapCreationTest