#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "LdapLayer.h"

PTF_TEST_CASE(LdapParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ldap_search_res_entry.dat");

	pcpp::Packet searchRequestPacket(&rawPacket1);
	pcpp::Packet searchResEntryPacket(&rawPacket2);

	// SearchRequest
	{
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

	// SearchResEntry
	{
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

	// Test tryGet
	{
		buffer1[127] = 0x31;
		pcpp::Packet malformedSearchRequestPacket(&rawPacket1);
		auto malformedSearchRequestLayer = malformedSearchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(malformedSearchRequestLayer);
		uint16_t messageId;
		PTF_ASSERT_TRUE(malformedSearchRequestLayer->tryGet(&pcpp::LdapSearchRequestLayer::getMessageID, messageId));
		PTF_ASSERT_EQUAL(messageId, 9);
		std::vector<std::string> attrs;
		PTF_ASSERT_FALSE(malformedSearchRequestLayer->tryGet(&pcpp::LdapSearchRequestLayer::getAttributes, attrs));
		buffer1[127] = 0x30; // restore
	}

	// Negative tests

	// Unknown LDAP operation type (30)
	{
		buffer1[72] = 0x7e;
		pcpp::Packet unknownLdapOperationTypePacket(&rawPacket1);
		PTF_ASSERT_NULL(unknownLdapOperationTypePacket.getLayerOfType<pcpp::LdapSearchRequestLayer>());
		PTF_ASSERT_NULL(unknownLdapOperationTypePacket.getLayerOfType<pcpp::LdapLayer>());
		buffer1[72] = 0x63; // restore
	}

	// Root record isn't an ASN.1 sequence (but a set)
	{
		buffer1[66] = 0x31;
		pcpp::Packet unexpectedRootAsn1RecordPacket(&rawPacket1);
		PTF_ASSERT_NULL(unexpectedRootAsn1RecordPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>());
		PTF_ASSERT_NULL(unexpectedRootAsn1RecordPacket.getLayerOfType<pcpp::LdapLayer>());
		buffer1[66] = 0x30; // restore
	}

	// Bad ASN.1 data
	{
		buffer1[68] = 0x01;
		pcpp::Packet badAsn1Packet(&rawPacket1);
		PTF_ASSERT_NULL(badAsn1Packet.getLayerOfType<pcpp::LdapSearchRequestLayer>());
		PTF_ASSERT_NULL(badAsn1Packet.getLayerOfType<pcpp::LdapLayer>());
		buffer1[68] = 0xe1; // restore
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

	// SearchResEntry
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
} // LdapCreationTest