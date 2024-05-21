#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "LdapLayer.h"

PTF_TEST_CASE(LdapParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

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
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getReferral(), "");
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
		PTF_ASSERT_EQUAL(modifyResponseLayer->getReferral(), "");
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
		PTF_ASSERT_EQUAL(addResponseLayer->getReferral(), "");
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
		PTF_ASSERT_EQUAL(deleteResponseLayer->getReferral(), "");
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