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

	auto searchRequestLayer = searchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
	PTF_ASSERT_NOT_NULL(searchRequestLayer);
	PTF_ASSERT_EQUAL(searchRequestLayer->getMessageID(), 9);
	PTF_ASSERT_EQUAL(searchRequestLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchRequest, enumclass);
	PTF_ASSERT_EQUAL(searchRequestLayer->getBaseObject(), "cn=schema");
	PTF_ASSERT_EQUAL(searchRequestLayer->getScope(), pcpp::LdapSearchRequestLayer::SearchRequestScope::BaseObject, enumclass);
	PTF_ASSERT_EQUAL(searchRequestLayer->getDerefAlias(), pcpp::LdapSearchRequestLayer::DerefAliases::DerefAlways, enumclass);
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

	auto searchResultEntryLayer = searchResEntryPacket.getLayerOfType<pcpp::LdapSearchResultEntryLayer>();
	PTF_ASSERT_NOT_NULL(searchResultEntryLayer);
	PTF_ASSERT_EQUAL(searchResultEntryLayer->getMessageID(), 16);
	PTF_ASSERT_EQUAL(searchResultEntryLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultEntry, enumclass);
	PTF_ASSERT_EQUAL(searchResultEntryLayer->getObjectName(), "cn=b.smith,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org");
}
