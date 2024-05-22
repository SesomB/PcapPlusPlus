#include "LdapLayer.h"
#include <iostream>

namespace pcpp
{

	LdapLayer::LdapLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = LDAP;
		m_Asn1Record = std::move(asn1Record);
	}

	void LdapLayer::init(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords)
	{
		Asn1IntegerRecord messageIdRecord(messageId);
		Asn1ConstructedRecord messageRootRecord(Asn1TagClass::Application, operationType, messageRecords);
		Asn1SequenceRecord rootRecord({&messageIdRecord, &messageRootRecord});

		auto encodedRecord = rootRecord.encode();
		m_DataLen = encodedRecord.size();
		m_Data = new uint8_t[m_DataLen];
		std::copy(encodedRecord.begin(), encodedRecord.end(), m_Data);
		m_Protocol = LDAP;
		m_Asn1Record = Asn1Record::decode(m_Data, m_DataLen, true);
	}

	std::string LdapLayer::toString() const
	{
		auto extendedInfo = getExtendedStringInfo();
		return "LDAP Layer, " + getLdapOperationType().toString() + (extendedInfo.empty() ? "" : ", " + extendedInfo);
	}

	LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		try
		{
			auto asn1Record = Asn1Record::decode(data, dataLen, true);
			auto operationType = LdapOperationType::fromIntValue(asn1Record->castAs<Asn1SequenceRecord>()->getSubRecords().at(1)->getTagType());
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
				case LdapOperationType::SearchResultDone:
				{
					return new LdapSearchResultDoneLayer(asn1Record, data, dataLen, prevLayer, packet);
				}
				case LdapOperationType::ModifyResponse:
				{
					return new LdapModifyResponseLayer(asn1Record, data, dataLen, prevLayer, packet);
				}
				case LdapOperationType::AddResponse:
				{
					return new LdapAddResponseLayer(asn1Record, data, dataLen, prevLayer, packet);
				}
				case LdapOperationType::DelResponse:
				{
					return new LdapDeleteResponseLayer(asn1Record, data, dataLen, prevLayer, packet);
				}
				default:
				{
					return nullptr;
				}
			}
		}
		catch (...)
		{
			return nullptr;
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
		return LdapOperationType::fromIntValue(getMessageRecord()->getTagType());
	}

	LdapResponse::LdapResponse(uint16_t messageId, const LdapOperationType& operationType, const LdapResultCode& resultCode,
		const std::string& matchedDN, const std::string& diagnosticMessage)
	{
		Asn1EnumeratedRecord resultCodeRecord(resultCode);
		Asn1OctetStringRecord matchedDNRecord(matchedDN);
		Asn1OctetStringRecord diagnosticMessageRecord(diagnosticMessage);

		std::vector<Asn1Record*> messageSubRecords = {&resultCodeRecord, &matchedDNRecord, &diagnosticMessageRecord};

		LdapLayer::init(messageId, operationType, messageSubRecords);
	}

	LdapResultCode LdapResponse::getResultCode() const
	{
		return LdapResultCode::fromIntValue(getMessageRecord()->getSubRecords().at(0)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	std::string LdapResponse::getMatchedDN() const
	{
		return getMessageRecord()->getSubRecords().at(1)->castAs<Asn1OctetStringRecord>()->getValue();
	}
	std::string LdapResponse::getDiagnosticMessage() const
	{
		return getMessageRecord()->getSubRecords().at(2)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	LdapSearchRequestLayer::LdapSearchRequestLayer(
		uint16_t messageId, const std::string& baseObject, SearchRequestScope scope, DerefAliases derefAliases,
		uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly, const std::vector<uint8_t>& filter,
		const std::vector<std::string>& attributes)
	{
		Asn1OctetStringRecord baseObjectRecord(baseObject);
		Asn1EnumeratedRecord scopeRecord(scope);
		Asn1EnumeratedRecord derefAliasesRecord(derefAliases);
		Asn1IntegerRecord sizeLimitRecord(sizeLimit);
		Asn1IntegerRecord timeLimitRecord(timeLimit);
		Asn1BooleanRecord typeOnlyRecord(typesOnly);
		auto filterRecord = Asn1Record::decode(filter.data(), filter.size(), false);

		PointerVector<Asn1Record> attributeSubRecords;
		for (const auto& attribute : attributes)
		{
			attributeSubRecords.pushBack(new Asn1OctetStringRecord(attribute));
		}
		Asn1SequenceRecord attributesRecord(attributeSubRecords);

		LdapLayer::init(messageId, LdapOperationType::SearchRequest, {&baseObjectRecord, &scopeRecord, &derefAliasesRecord, &sizeLimitRecord, &timeLimitRecord, &typeOnlyRecord, filterRecord.get(), &attributesRecord});
	}
	std::string LdapSearchRequestLayer::getBaseObject() const
	{
		return getMessageRecord()->getSubRecords().at(0)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	LdapSearchRequestLayer::SearchRequestScope LdapSearchRequestLayer::getScope() const
	{
		return LdapSearchRequestLayer::SearchRequestScope::fromIntValue(getMessageRecord()->getSubRecords().at(1)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	LdapSearchRequestLayer::DerefAliases LdapSearchRequestLayer::getDerefAlias() const
	{
		return LdapSearchRequestLayer::DerefAliases::fromIntValue(getMessageRecord()->getSubRecords().at(2)->castAs<Asn1EnumeratedRecord>()->getValue());
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
		auto baseObject = getBaseObject();
		if (baseObject.empty())
		{
			baseObject = "ROOT";
		}

		return "\"" + baseObject + "\", " + getScope().toString();
	}

	LdapSearchResultEntryLayer::LdapSearchResultEntryLayer(uint16_t messageId, const std::string& objectName, const std::vector<LdapPartialAttribute>& attributes)
	{
		PointerVector<Asn1Record> attributesSubRecords;
		for (const auto& attribute : attributes)
		{
			PointerVector<Asn1Record> valuesSubRecords;
			for (const auto& value : attribute.values)
			{
				valuesSubRecords.pushBack(new Asn1OctetStringRecord(value));
			}

			Asn1OctetStringRecord typeRecord(attribute.type);
			Asn1SetRecord valuesRecord(valuesSubRecords);

			attributesSubRecords.pushBack(new Asn1SequenceRecord({&typeRecord, &valuesRecord}));
		}

		Asn1OctetStringRecord objectNameRecord(objectName);
		Asn1SequenceRecord attributesRecord(attributesSubRecords);

		LdapLayer::init(messageId, LdapOperationType::SearchResultEntry, {&objectNameRecord, &attributesRecord});
	}

	std::string LdapSearchResultEntryLayer::getObjectName() const
	{
		return getMessageRecord()->getSubRecords().at(0)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	std::vector<LdapPartialAttribute> LdapSearchResultEntryLayer::getAttributes() const
	{
		std::vector<LdapPartialAttribute> result;

		auto attributes = getMessageRecord()->getSubRecords().at(1)->castAs<Asn1SequenceRecord>();
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