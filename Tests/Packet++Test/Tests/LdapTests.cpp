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
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_controls1.dat", pcpp::LINKTYPE_LINUX_SLL);
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

	// Test tryGet
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
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_controls1.dat", pcpp::LINKTYPE_LINUX_SLL);
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
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_controls2.dat");
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