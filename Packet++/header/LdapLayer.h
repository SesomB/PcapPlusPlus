#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <sstream>
#include <string>

namespace pcpp
{
	enum class LdapOperationType : uint8_t
	{
		BindRequest = 0,
		BindResponse = 1,
		UnbindRequest = 2,
		SearchRequest = 3,
		SearchResultEntry = 4,
		SearchResultDone = 5,
		ModifyRequest = 6,
		ModifyResponse = 7,
		AddRequest = 8,
		AddResponse = 9,
		DelRequest = 10,
		DelResponse = 11,
		ModifyDNRequest = 12,
		ModifyDNResponse = 13,
		CompareRequest = 14,
		CompareResponse = 15,
		AbandonRequest = 16,
		SearchResultReference = 19,
		ExtendedRequest = 23,
		ExtendedResponse = 24,
		IntermediateResponse = 25
	};

	/**
	 * @class LdapLayer
	 * TBD
	 */
	class LdapLayer : public Layer
	{
	public:
		~LdapLayer() {}

		uint16_t getMessageID() const;

		LdapOperationType getLdapOperationType() const;

		std::string getLdapOperationTypeAsString() const;

		// implement abstract methods

		/**
		 * Does nothing for this layer (ArpLayer is always last)
		 */
		void parseNextLayer() override {}

		size_t getHeaderLen() const override { return m_DataLen; }

		void computeCalculateFields() override {}

		OsiModelLayer getOsiModelLayer() const override{ return OsiModelApplicationLayer; }

		std::string toString() const override;

		static bool isLdapPort(uint16_t port) { return port == 389; }

		static LdapLayer* parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	protected:
		std::unique_ptr<Asn1Record> m_Asn1Record;

		LdapLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
		Asn1SequenceRecord* getAsn1Record() const;
		Asn1ConstructedRecord* getMessageRecord() const;
		virtual std::string getExtendedStringInfo() const {return ""; }
	};

	struct LdapPartialAttribute
	{
		std::string type;
		std::vector<std::string> values;
	};

	class LdapSearchRequestLayer : public LdapLayer
	{
	public:
		enum class SearchRequestScope : uint8_t
		{
			BaseObject = 0,
			SingleLevel = 1,
			WholeSubtree = 2,
			Unknown = 255
		};

		enum class DerefAliases : uint8_t
		{
			NeverDerefAliases = 0,
			DerefInSearching = 1,
			DerefFindingBaseObj = 2,
			DerefAlways = 3,
			Unknown = 255
		};

		LdapSearchRequestLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: LdapLayer(asn1Record, data, dataLen, prevLayer, packet) {}

		std::string getBaseObject() const;
		SearchRequestScope getScope() const;
		DerefAliases getDerefAlias() const;
		uint8_t getSizeLimit() const;
		uint8_t getTimeLimit() const;
		bool getTypesOnly() const;
		// TODO: std::string getFilter();
		std::vector<std::string> getAttributes() const;

		// implement abstract methods

	protected:
		std::string getExtendedStringInfo() const override;
	};

	class LdapSearchResultEntryLayer : public LdapLayer
	{
	public:
		LdapSearchResultEntryLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: LdapLayer(asn1Record, data, dataLen, prevLayer, packet) {}

		std::string getObjectName() const;
		std::vector<LdapPartialAttribute> getAttributes() const;
	};
} // namespace pcpp
