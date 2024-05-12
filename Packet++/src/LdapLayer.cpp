#include "LdapLayer.h"
#include <iostream>

namespace pcpp
{

	LdapLayer::LdapLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = LDAP;
		m_Asn1Record = std::move(asn1Record);
	}

	std::string LdapLayer::toString() const
	{
		auto extendedInfo = getExtendedStringInfo();
		return "LDAP Layer, " + getLdapOperationTypeAsString() + (extendedInfo.empty() ? "" : ", " + extendedInfo);
	}

	LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		//TODO: catch all possible exceptions

		auto asn1Record = Asn1Record::decode(data, dataLen, false);
		auto operationType = static_cast<LdapOperationType>(asn1Record->castAs<Asn1SequenceRecord>()->getSubRecords().at(1)->getTagType());
		switch (operationType)
		{
			case LdapOperationType::SearchRequest:
			{
				return new LdapSearchRequestLayer(asn1Record, data, dataLen, prevLayer, packet);
			}
			case LdapOperationType::SearchResultEntry:
			{
				return new LdapSearchResultEntryLayer(asn1Record, data, dataLen, prevLayer, packet);
			}
			default:
			{
				return nullptr;
			}
		}
	}

	Asn1SequenceRecord* LdapLayer::getAsn1Record() const
	{
		return m_Asn1Record->castAs<Asn1SequenceRecord>();
	}

	Asn1ConstructedRecord* LdapLayer::getMessageRecord() const
	{
		return getAsn1Record()->getSubRecords().at(1)->castAs<Asn1ConstructedRecord>();
	}

	uint16_t LdapLayer::getMessageID() const
	{
		return getAsn1Record()->getSubRecords().at(0)->castAs<Asn1IntegerRecord>()->getValue();
	}

	LdapOperationType LdapLayer::getLdapOperationType() const
	{
		// TODO: check the enum value
		return static_cast<LdapOperationType>(getMessageRecord()->getTagType());
	}

	std::string LdapLayer::getLdapOperationTypeAsString() const
	{
		switch (getLdapOperationType())
		{
			case LdapOperationType::BindRequest:
			{
				return "BindRequest";
			}
			case LdapOperationType::BindResponse:
			{
				return "BindResponse";
			}
			case LdapOperationType::UnbindRequest:
			{
				return "UnbindRequest";
			}
			case LdapOperationType::SearchRequest:
			{
				return "SearchRequest";
			}
			case LdapOperationType::SearchResultEntry:
			{
				return "SearchResultEntry";
			}
			case LdapOperationType::SearchResultDone:
			{
				return "SearchResultDone";
			}
			case LdapOperationType::ModifyRequest:
			{
				return "ModifyRequest";
			}
			case LdapOperationType::ModifyResponse:
			{
				return "ModifyResponse";
			}
			case LdapOperationType::AddRequest:
			{
				return "AddRequest";
			}
			case LdapOperationType::AddResponse:
			{
				return "AddResponse";
			}
			case LdapOperationType::DelRequest:
			{
				return "DelRequest";
			}
			case LdapOperationType::DelResponse:
			{
				return "DelResponse";
			}
			case LdapOperationType::ModifyDNRequest:
			{
				return "ModifyDNRequest";
			}
			case LdapOperationType::ModifyDNResponse:
			{
				return "ModifyDNResponse";
			}
			case LdapOperationType::CompareRequest:
			{
				return "CompareRequest";
			}
			case LdapOperationType::CompareResponse:
			{
				return "CompareResponse";
			}
			case LdapOperationType::AbandonRequest:
			{
				return "AbandonRequest";
			}
			case LdapOperationType::SearchResultReference:
			{
				return "SearchResultReference";
			}
			case LdapOperationType::ExtendedRequest:
			{
				return "ExtendedRequest";
			}
			case LdapOperationType::ExtendedResponse:
			{
				return "ExtendedResponse";
			}
			case LdapOperationType::IntermediateResponse:
			{
				return "IntermediateResponse";
			}
			default:
			{
				return "Unknown";
			}
		}
	}

	std::string LdapSearchRequestLayer::getBaseObject() const
	{
		return getMessageRecord()->getSubRecords().at(0)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	LdapSearchRequestLayer::SearchRequestScope LdapSearchRequestLayer::getScope() const
	{
		// TODO: check enum value
		return static_cast<LdapSearchRequestLayer::SearchRequestScope>(getMessageRecord()->getSubRecords().at(1)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	LdapSearchRequestLayer::DerefAliases LdapSearchRequestLayer::getDerefAlias() const
	{
		// TODO: check enum value
		return static_cast<LdapSearchRequestLayer::DerefAliases>(getMessageRecord()->getSubRecords().at(2)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	uint8_t LdapSearchRequestLayer::getSizeLimit() const
	{
		return static_cast<uint8_t>(getMessageRecord()->getSubRecords().at(3)->castAs<Asn1IntegerRecord>()->getValue());
	}

	uint8_t LdapSearchRequestLayer::getTimeLimit() const
	{
		return static_cast<uint8_t>(getMessageRecord()->getSubRecords().at(4)->castAs<Asn1IntegerRecord>()->getValue());
	}

	bool LdapSearchRequestLayer::getTypesOnly() const
	{
		return getMessageRecord()->getSubRecords().at(5)->castAs<Asn1BooleanRecord>()->getValue();
	}

	std::vector<std::string> LdapSearchRequestLayer::getAttributes() const
	{
		std::vector<std::string> result;
		auto attributesRecord = getMessageRecord()->getSubRecords().at(7)->castAs<Asn1SequenceRecord>();
		for (auto attribute : attributesRecord->getSubRecords())
		{
			result.push_back(attribute->castAs<Asn1OctetStringRecord>()->getValue());
		}

		return result;
	}

	std::string LdapSearchRequestLayer::getExtendedStringInfo() const
	{
		std::string scope = "";
		switch (getScope())
		{
			case SearchRequestScope::BaseObject:
			{
				scope = "BaseObject";
				break;
			}
			case SearchRequestScope::SingleLevel:
			{
				scope = "SingleLevel";
				break;
			}
			case SearchRequestScope::WholeSubtree:
			{
				scope = "WholeSubtree";
				break;
			}
			default:
			{
				scope = "Unknown";
				break;
			}
		}

		auto baseObject = getBaseObject();
		if (baseObject.empty())
		{
			baseObject = "ROOT";
		}

		return "\"" + getBaseObject() + "\", " + scope;
	}

	std::string LdapSearchResultEntryLayer::getObjectName() const
	{
		return getMessageRecord()->getSubRecords().at(0)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	std::vector<LdapPartialAttribute> LdapSearchResultEntryLayer::getAttributes() const
	{
		std::vector<LdapPartialAttribute> result;

		auto attributes = getMessageRecord()->getSubRecords().at(0)->castAs<Asn1SequenceRecord>();
		for (auto attributeRecord : attributes->getSubRecords())
		{
			auto attrAsSequence = attributeRecord->castAs<Asn1SequenceRecord>();

			auto type = attrAsSequence->getSubRecords().at(0)->castAs<Asn1OctetStringRecord>()->getValue();

			std::vector<std::string> values;
			auto valuesRecord = attrAsSequence->getSubRecords().at(1)->castAs<Asn1SetRecord>();
			for (auto valueRecord : valuesRecord->getSubRecords())
			{
				values.push_back(valueRecord->castAs<Asn1OctetStringRecord>()->getValue());
			}

			LdapPartialAttribute ldapPartialAttribute = {type, values};
			result.push_back(ldapPartialAttribute);
		}

		return result;
	}
}
