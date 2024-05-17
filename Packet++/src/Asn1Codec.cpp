#define LOG_MODULE PacketLogModuleAsn1Codec

#include "Asn1Codec.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"
#include <iostream>
#include <sstream>
#include <numeric>
#include <cstring>
#include <cmath>
#include <limits>

#if defined(_WIN32)
#undef max
#endif

namespace pcpp {
	std::unique_ptr<Asn1Record> Asn1Record::decode(const uint8_t* data, size_t dataLen, bool lazy)
	{
		auto record = decodeInternal(data, dataLen ,lazy);
		return std::unique_ptr<Asn1Record>(record);
	}

	uint8_t Asn1Record::encodeTag()
	{
		uint8_t tagByte;

		switch (m_TagClass)
		{
			case Asn1TagClass::Private:
			{
				tagByte = 0xc0;
				break;
			}
			case Asn1TagClass::ContextSpecific:
			{
				tagByte = 0x80;
				break;
			}
			case Asn1TagClass::Application:
			{
				tagByte = 0x40;
				break;
			}
			default:
			{
				tagByte = 0;
				break;
			}
		}

		if (m_IsConstructed)
		{
			tagByte |= 0x20;
		}

		auto tagType = m_TagType & 0x1f;
		tagByte |= tagType;

		return tagByte;
	}

	std::vector<uint8_t> Asn1Record::encodeLength() const
	{
		std::vector<uint8_t> result;

		if (m_ValueLength < 128)
		{
			result.push_back(static_cast<uint8_t>(m_ValueLength));
			return result;
		}

		// Assuming the size is always less than 256
		uint8_t firstByte = 0x80 | 0x01;
		result.push_back(firstByte);
		result.push_back(m_ValueLength);

		return result;
	}

	std::vector<uint8_t> Asn1Record::encode()
	{
		std::vector<uint8_t> result;

		result.push_back(encodeTag());

		auto lengthBytes = encodeLength();
		result.insert(result.end(), lengthBytes.begin(), lengthBytes.end());

		auto encodedValue = encodeValue();
		result.insert(result.end(), encodedValue.begin(), encodedValue.end());

		return result;
	}

	Asn1Record* Asn1Record::decodeInternal(const uint8_t* data, size_t dataLen, bool lazy)
	{
		int tagLen;
		auto decodedRecord = decodeTagAndCreateRecord(data, dataLen, tagLen);

		int lengthLen;
		try
		{
			lengthLen = decodedRecord->decodeLength(data + tagLen, dataLen - tagLen);
		}
		catch (...)
		{
			delete decodedRecord;
			throw;
		}

		if (static_cast<int>(dataLen) - tagLen - lengthLen - static_cast<int>(decodedRecord->m_ValueLength) < 0)
		{
			delete decodedRecord;
			throw std::invalid_argument("Cannot decode ASN.1 record, data doesn't contain the entire record");
		}

		decodedRecord->m_TotalLength = tagLen + lengthLen + decodedRecord->m_ValueLength;

		if (!lazy)
		{
			try
			{
				decodedRecord->decodeValue(const_cast<uint8_t*>(data) + tagLen + lengthLen, lazy);
			}
			catch (...)
			{
				delete decodedRecord;
				throw;
			}

		}
		else
		{
			decodedRecord->m_EncodedValue = const_cast<uint8_t*>(data) + tagLen + lengthLen;
		}

		return decodedRecord;
	}

	Asn1UniversalTagType Asn1Record::getUniversalTagType() const
	{
		if (m_TagClass == Asn1TagClass::Universal)
		{
			return static_cast<Asn1UniversalTagType>(m_TagType);
		}

		return Asn1UniversalTagType::NotApplicable;
	}

	Asn1Record* Asn1Record::decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen, int& tagLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 record tag");
		}

		tagLen = 1;

		Asn1TagClass tagClass = Asn1TagClass::Universal;

		// Check first 2 bits
		auto tagClassBits = data[0] & 0xc0;
		if (tagClassBits == 0)
		{
			tagClass = Asn1TagClass::Universal;
		}
		else if ((tagClassBits & 0xc0) == 0xc0)
		{
			tagClass = Asn1TagClass::Private;
		}
		else if ((tagClassBits & 0x80) == 0x80)
		{
			tagClass = Asn1TagClass::ContextSpecific;
		}
		else if ((tagClassBits & 0x40) == 0x40)
		{
			tagClass = Asn1TagClass::Application;
		}

		// Check bit 6
		auto tagTypeBits = data[0] & 0x20;
		bool isConstructed = (tagTypeBits != 0);

		// Check last 5 bits
		auto tagType = data[0] & 0x1f;
		if (tagType == 0x1f)
		{
			if (dataLen < 2)
			{
				throw std::invalid_argument("Cannot decode ASN.1 record tag");
			}

			if ((data[1] & 0x80) != 0)
			{
				throw std::invalid_argument("ASN.1 tags with value larger than 127 are not supported");
			}

			tagType = data[1] & 0x7f;
			tagLen = 2;
		}

		Asn1Record* newRecord;

		if (isConstructed)
		{
			if (tagClass == Asn1TagClass::Universal)
			{
				switch (static_cast<Asn1UniversalTagType>(tagType))
				{
					case Asn1UniversalTagType::Sequence:
					{
						newRecord = new Asn1SequenceRecord();
						break;
					}
					case Asn1UniversalTagType::Set:
					{
						newRecord = new Asn1SetRecord();
						break;
					}
					default:
					{
						newRecord = new Asn1ConstructedRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1ConstructedRecord();
			}
		}
		else
		{
			if (tagClass == Asn1TagClass::Universal)
			{
				auto asn1UniversalTagType = static_cast<Asn1UniversalTagType>(tagType);
				switch (asn1UniversalTagType)
				{
					case Asn1UniversalTagType::Integer:
					{
						newRecord = new Asn1IntegerRecord();
						break;
					}
					case Asn1UniversalTagType::Enumerated:
					{
						newRecord = new Asn1EnumeratedRecord();
						break;
					}
					case Asn1UniversalTagType::OctetString:
					{
						newRecord = new Asn1OctetStringRecord();
						break;
					}
					case Asn1UniversalTagType::Boolean:
					{
						newRecord = new Asn1BooleanRecord();
						break;
					}
					case Asn1UniversalTagType::Null:
					{
						newRecord = new Asn1NullRecord();
						break;
					}
					default:
					{
						newRecord = new Asn1GenericRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1GenericRecord();
			}
		}

		newRecord->m_TagClass = tagClass;
		newRecord->m_IsConstructed = isConstructed;
		newRecord->m_TagType = tagType;

		return newRecord;
	}

	int Asn1Record::decodeLength(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 record length");
		}

		// Check 8th bit
		auto lengthForm = data[0] & 0x80;

		auto numberLengthBytes = 1;

		// Check if the tag is using more than one byte
		// 8th bit at 0 means the length only uses one byte
		// 8th bit at 1 means the length uses more than one byte. The number of bytes is encoded in the other 7 bits
		if (lengthForm != 0)
		{
			auto additionalLengthBytes = data[0] & 0x7F;
			if (static_cast<int>(dataLen) < additionalLengthBytes + 1)
			{
				throw std::invalid_argument("Cannot decode ASN.1 record length");
			}
			for (auto index = additionalLengthBytes; index > 0; --index)
			{
				m_ValueLength += data[index] * static_cast<int>(std::pow(256, (additionalLengthBytes - index)));
			}
			numberLengthBytes += additionalLengthBytes;
		}
		else
		{
			m_ValueLength = data[0];
		}

		return numberLengthBytes;
	}

	void Asn1Record::decodeValueIfNeeded()
	{
		if (m_EncodedValue != nullptr)
		{
			decodeValue(m_EncodedValue, true);
			m_EncodedValue = nullptr;
		}
	}

	std::string Asn1Record::toString()
	{
		auto lines = toStringInternal();

		auto commaSeparated = [](std::string a, std::string b)
		{
			return std::move(a) + '\n' + std::move(b);
		};

		return std::accumulate(std::next(lines.begin()), lines.end(),lines[0], commaSeparated);
	}

	std::vector<std::string> Asn1Record::toStringInternal()
	{
		std::ostringstream stream;

		auto universalType = getUniversalTagType();
		if (universalType == Asn1UniversalTagType::NotApplicable)
		{
			switch (m_TagClass)
			{
				case Asn1TagClass::ContextSpecific:
				{
					stream << "ContextSpecific";
					break;
				}
				case Asn1TagClass::Application:
				{
					stream << "Application";
					break;
				}
				case Asn1TagClass::Private:
				{
					stream << "Private";
					break;
				}
				default:
				{
					stream << "Unknown";
				}
			}
			stream << " (" << static_cast<int>(m_TagType) << ")";
		}
		else
		{
			switch (universalType)
			{
				case Asn1UniversalTagType::EndOfContent:
				{
					stream << "EndOfContent";
					break;
				}
				case Asn1UniversalTagType::Boolean:
				{
					stream << "Boolean";
					break;
				}
				case Asn1UniversalTagType::Integer:
				{
					stream << "Integer";
					break;
				}
				case Asn1UniversalTagType::BitString:
				{
					stream << "BitString";
					break;
				}
				case Asn1UniversalTagType::OctetString:
				{
					stream << "OctetString";
					break;
				}
				case Asn1UniversalTagType::Null:
				{
					stream << "Null";
					break;
				}
				case Asn1UniversalTagType::ObjectIdentifier:
				{
					stream << "ObjectIdentifier";
					break;
				}
				case Asn1UniversalTagType::ObjectDescriptor:
				{
					stream << "ObjectDescriptor";
					break;
				}
				case Asn1UniversalTagType::External:
				{
					stream << "External";
					break;
				}
				case Asn1UniversalTagType::Real:
				{
					stream << "Real";
					break;
				}
				case Asn1UniversalTagType::Enumerated:
				{
					stream << "Enumerated";
					break;
				}
				case Asn1UniversalTagType::EmbeddedPDV:
				{
					stream << "EmbeddedPDV";
					break;
				}
				case Asn1UniversalTagType::UTF8String:
				{
					stream << "UTF8String";
					break;
				}
				case Asn1UniversalTagType::RelativeObjectIdentifier:
				{
					stream << "RelativeObjectIdentifier";
					break;
				}
				case Asn1UniversalTagType::Time:
				{
					stream << "Time";
					break;
				}
				case Asn1UniversalTagType::Reserved:
				{
					stream << "Reserved";
					break;
				}
				case Asn1UniversalTagType::Sequence:
				{
					stream << "Sequence";
					break;
				}
				case Asn1UniversalTagType::Set:
				{
					stream << "Set";
					break;
				}
				case Asn1UniversalTagType::NumericString:
				{
					stream << "NumericString";
					break;
				}
				case Asn1UniversalTagType::PrintableString:
				{
					stream << "PrintableString";
					break;
				}
				case Asn1UniversalTagType::T61String:
				{
					stream << "T61String";
					break;
				}
				case Asn1UniversalTagType::VideotexString:
				{
					stream << "VideotexString";
					break;
				}
				case Asn1UniversalTagType::IA5String:
				{
					stream << "IA5String";
					break;
				}
				case Asn1UniversalTagType::UTCTime:
				{
					stream << "UTCTime";
					break;
				}
				case Asn1UniversalTagType::GeneralizedTime:
				{
					stream << "GeneralizedTime";
					break;
				}
				case Asn1UniversalTagType::GraphicString:
				{
					stream << "GraphicString";
					break;
				}
				case Asn1UniversalTagType::VisibleString:
				{
					stream << "VisibleString";
					break;
				}
				case Asn1UniversalTagType::GeneralString:
				{
					stream << "GeneralString";
					break;
				}
				case Asn1UniversalTagType::UniversalString:
				{
					stream << "UniversalString";
					break;
				}
				case Asn1UniversalTagType::CharacterString:
				{
					stream << "CharacterString";
					break;
				}
				case Asn1UniversalTagType::BMPString:
				{
					stream << "BMPString";
					break;
				}
				case Asn1UniversalTagType::Date:
				{
					stream << "Date";
					break;
				}
				case Asn1UniversalTagType::TimeOfDay:
				{
					stream << "TimeOfDay";
					break;
				}
				case Asn1UniversalTagType::DateTime:
				{
					stream << "DateTime";
					break;
				}
				case Asn1UniversalTagType::Duration:
				{
					stream << "Duration";
					break;
				}
				case Asn1UniversalTagType::ObjectIdentifierIRI:
				{
					stream << "ObjectIdentifierIRI";
					break;
				}
				case Asn1UniversalTagType::RelativeObjectIdentifierIRI:
				{
					stream << "RelativeObjectIdentifierIRI";
					break;
				}
				default:
				{
					stream << "Unknown";
					break;
				}
			}
		}

		if (m_IsConstructed)
		{
			stream << " (constructed)";
		}

		stream << ", Length: " << m_TotalLength - m_ValueLength << "+" << m_ValueLength;

		return std::vector<std::string>({stream.str()});
	}


	Asn1GenericRecord::Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value, size_t valueLen)
	{
		m_TagType = tagType;
		m_TagClass = tagClass;
		m_IsConstructed = isConstructed;
		m_Value = new uint8_t[valueLen];
		m_FreeValueOnDestruction = true;
		memcpy(m_Value, value, valueLen);
		m_ValueLength = valueLen;
		m_TotalLength = m_ValueLength + 2;
	}

	Asn1GenericRecord::~Asn1GenericRecord()
	{
		if (m_Value && m_FreeValueOnDestruction)
		{
			delete m_Value;
		}
	}

	void Asn1GenericRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = data;
	}

	std::vector<uint8_t> Asn1GenericRecord::encodeValue() const
	{
		return {m_Value, m_Value + m_ValueLength};
	}

	Asn1ConstructedRecord::Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType, const std::vector<Asn1Record*>& subRecords)
	{
		init(tagClass, tagType, subRecords.begin(), subRecords.end());
	}

	Asn1ConstructedRecord::Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType, const PointerVector<Asn1Record>& subRecords)
	{
		init(tagClass, tagType, subRecords.begin(), subRecords.end());
	}

	void Asn1ConstructedRecord::decodeValue(uint8_t* data, bool lazy)
	{
		if (!(data || m_ValueLength))
		{
			return;
		}

		auto value = data;
		auto valueLen = m_ValueLength;

		while (valueLen > 0)
		{
			auto subRecord = Asn1Record::decodeInternal(value, valueLen, lazy);
			value += subRecord->getTotalLength();
			valueLen -= subRecord->getTotalLength();

			m_SubRecords.pushBack(subRecord);
		}
	}

	std::vector<uint8_t> Asn1ConstructedRecord::encodeValue() const
	{
		std::vector<uint8_t> result;
		result.reserve(m_ValueLength);

		for (auto record : m_SubRecords)
		{
			auto encodedRecord = record->encode();
			result.insert(result.end(), std::make_move_iterator(encodedRecord.begin()), std::make_move_iterator(encodedRecord.end()));
		}
		return result;
	}

	std::vector<std::string> Asn1ConstructedRecord::toStringInternal()
	{
		std::vector<std::string> result = {Asn1Record::toStringInternal().front()};
		for (auto subRecord : m_SubRecords)
		{
			for (const auto& line : subRecord->toStringInternal())
			{
				result.push_back("  " + line);
			}
		}
		return result;
	}

	Asn1SequenceRecord::Asn1SequenceRecord(const std::vector<Asn1Record*>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence), subRecords)
	{}

	Asn1SequenceRecord::Asn1SequenceRecord(const PointerVector<Asn1Record>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence), subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const std::vector<Asn1Record*>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const PointerVector<Asn1Record>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1PrimitiveRecord::Asn1PrimitiveRecord(Asn1UniversalTagType tagType) : Asn1Record()
	{
		m_TagType = static_cast<uint8_t >(tagType);
		m_TagClass = Asn1TagClass::Universal;
		m_IsConstructed = false;
	}

	Asn1IntegerRecord::Asn1IntegerRecord(uint32_t value) : Asn1PrimitiveRecord(Asn1UniversalTagType::Integer)
	{
		m_Value = value;

		if (m_Value <= std::numeric_limits<uint8_t>::max())
		{
			m_ValueLength = sizeof(uint8_t);
		}
		else if (value <= std::numeric_limits<uint16_t>::max())
		{
			m_ValueLength = sizeof(uint16_t);
		}
		else if (value <= std::pow(2, 3 * 8))
		{
			m_ValueLength = 3;
		}
		else
		{
			m_ValueLength = sizeof(uint32_t);
		}

		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1IntegerRecord::decodeValue(uint8_t* data, bool lazy)
	{
		switch (m_ValueLength)
		{
			case 1:
			{
				m_Value = *data;
				break;
			}
			case 2:
			{
				m_Value = be16toh(*reinterpret_cast<uint16_t*>(data));
				break;
			}
			case 3:
			{
				uint8_t tempData[4] = {0};
				memcpy(tempData + 1, data, 3);
				m_Value = be32toh(*reinterpret_cast<uint32_t*>(tempData));
				break;
			}
			case 4:
			{
				m_Value = be32toh(*reinterpret_cast<uint32_t*>(data));
				break;
			}
			default:
			{
				throw std::runtime_error("An integer ASN.1 record of more than 4 bytes is not supported");
			}
		}
	}

	std::vector<uint8_t> Asn1IntegerRecord::encodeValue() const
	{
		std::vector<uint8_t> result;
		result.reserve(m_ValueLength);

		switch (m_ValueLength)
		{
			case 1:
			{
				result.push_back(static_cast<uint8_t>(m_Value));
				break;
			}
			case 2:
			{
				uint8_t tempArr[sizeof(uint16_t)];
				auto hostValue = htobe16(static_cast<uint16_t>(m_Value));
				memcpy(tempArr, &hostValue, m_ValueLength);
				std::copy(tempArr, tempArr + m_ValueLength, std::back_inserter(result));
				break;
			}
			case 3:
			{
				uint8_t tempArr[sizeof(uint32_t)];
				auto hostValue = htobe32(static_cast<uint32_t>(m_Value));
				memcpy(tempArr, &hostValue, m_ValueLength + 1);
				std::copy(tempArr + 1, tempArr + m_ValueLength + 1, std::back_inserter(result));
				break;
			}
			case 4:
			{
				uint8_t tempArr[sizeof(uint32_t)];
				auto hostValue = htobe32(static_cast<uint32_t>(m_Value));
				memcpy(tempArr, &hostValue, m_ValueLength);
				std::copy(tempArr, tempArr + m_ValueLength, std::back_inserter(result));
				break;
			}
			default:
			{
				throw std::runtime_error("Integer value of more than 4 bytes is not supported");
			}
		}

		return result;
	}

	std::vector<std::string> Asn1IntegerRecord::toStringInternal()
	{
		return std::vector<std::string>({Asn1Record::toStringInternal().front() + ", Value: " + std::to_string(getValue())});
	}

	Asn1EnumeratedRecord::Asn1EnumeratedRecord(uint32_t value) : Asn1IntegerRecord(value)
	{
		m_TagType = static_cast<uint8_t>(Asn1UniversalTagType::Enumerated);
	}

	Asn1OctetStringRecord::Asn1OctetStringRecord(const std::string& value) : Asn1PrimitiveRecord(Asn1UniversalTagType::OctetString)
	{
		m_Value = value;
		m_ValueLength = value.size();
		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1OctetStringRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = std::string(reinterpret_cast<char*>(data), m_ValueLength);
	}

	std::vector<uint8_t> Asn1OctetStringRecord::encodeValue() const
	{
		return {m_Value.begin(), m_Value.end()};
	}

	std::vector<std::string> Asn1OctetStringRecord::toStringInternal()
	{
		return std::vector<std::string>({Asn1Record::toStringInternal().front() + ", Value: " + getValue()});
	}

	Asn1BooleanRecord::Asn1BooleanRecord(bool value) : Asn1PrimitiveRecord(Asn1UniversalTagType::Boolean)
	{
		m_Value = value;
		m_ValueLength = 1;
		m_TotalLength = 3;
	}

	void Asn1BooleanRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = data[0] != 0;
	}

	std::vector<uint8_t> Asn1BooleanRecord::encodeValue() const
	{
		uint8_t byte = (m_Value ? 0xff : 0x00);
		return { byte };
	}

	std::vector<std::string> Asn1BooleanRecord::toStringInternal()
	{
		return std::vector<std::string>({Asn1Record::toStringInternal().front() + ", Value: " + (getValue() ? "true" : "false")});
	}

	Asn1NullRecord::Asn1NullRecord() : Asn1PrimitiveRecord(Asn1UniversalTagType::Null)
	{
		m_ValueLength = 0;
		m_TotalLength = 2;
	}
}
