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

	// SearchResEntry
	auto searchResultEntryLayer = searchResEntryPacket.getLayerOfType<pcpp::LdapSearchResultEntryLayer>();
	PTF_ASSERT_NOT_NULL(searchResultEntryLayer);
	PTF_ASSERT_EQUAL(searchResultEntryLayer->getMessageID(), 16);
	PTF_ASSERT_EQUAL(searchResultEntryLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultEntry, enum);
	PTF_ASSERT_EQUAL(searchResultEntryLayer->getObjectName(), "cn=b.smith,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org");

	// Negative tests

	// Unknown LDAP operation type (30)
	buffer1[72] = 0x7e;
	pcpp::Packet unknownLdapOperationTypePacket(&rawPacket1);
	PTF_ASSERT_NULL(unknownLdapOperationTypePacket.getLayerOfType<pcpp::LdapSearchRequestLayer>());
	PTF_ASSERT_NULL(unknownLdapOperationTypePacket.getLayerOfType<pcpp::LdapLayer>());
	buffer1[72] = 0x63; // restore

	// Root record isn't an ASN.1 sequence (but a set)
	buffer1[66] = 0x31;
	pcpp::Packet unexpectedRootAsn1RecordPacket(&rawPacket1);
	PTF_ASSERT_NULL(unexpectedRootAsn1RecordPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>());
	PTF_ASSERT_NULL(unexpectedRootAsn1RecordPacket.getLayerOfType<pcpp::LdapLayer>());
	buffer1[66] = 0x30; // restore

	// Bad ASN.1 data
	buffer1[68] = 0x01;
	pcpp::Packet badAsn1Packet(&rawPacket1);
	PTF_ASSERT_NULL(badAsn1Packet.getLayerOfType<pcpp::LdapSearchRequestLayer>());
	PTF_ASSERT_NULL(badAsn1Packet.getLayerOfType<pcpp::LdapLayer>());
	buffer1[68] = 0xe1; // restore
}
