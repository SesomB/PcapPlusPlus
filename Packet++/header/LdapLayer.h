#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <sstream>
#include <string>

namespace pcpp
{
	class LdapOperationType
	{
	public:
		enum Value : uint8_t
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
			IntermediateResponse = 25,
			Unknown = 255
		};

		LdapOperationType() = default;
		constexpr LdapOperationType(Value value) : m_Value(value) { }
		constexpr operator Value() const { return m_Value; }

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

		std::string toString() const
		{
			switch (m_Value)
			{
				case LdapOperationType::BindRequest:
					return "BindRequest";
				case LdapOperationType::BindResponse:
					return "BindResponse";
				case LdapOperationType::UnbindRequest:
					return "UnbindRequest";
				case LdapOperationType::SearchRequest:
					return "SearchRequest";
				case LdapOperationType::SearchResultEntry:
					return "SearchResultEntry";
				case LdapOperationType::SearchResultDone:
					return "SearchResultDone";
				case LdapOperationType::ModifyRequest:
					return "ModifyRequest";
				case LdapOperationType::ModifyResponse:
					return "ModifyResponse";
				case LdapOperationType::AddRequest:
					return "AddRequest";
				case LdapOperationType::AddResponse:
					return "AddResponse";
				case LdapOperationType::DelRequest:
					return "DelRequest";
				case LdapOperationType::DelResponse:
					return "DelResponse";
				case LdapOperationType::ModifyDNRequest:
					return "ModifyDNRequest";
				case LdapOperationType::ModifyDNResponse:
					return "ModifyDNResponse";
				case LdapOperationType::CompareRequest:
					return "CompareRequest";
				case LdapOperationType::CompareResponse:
					return "CompareResponse";
				case LdapOperationType::AbandonRequest:
					return "AbandonRequest";
				case LdapOperationType::SearchResultReference:
					return "SearchResultReference";
				case LdapOperationType::ExtendedRequest:
					return "ExtendedRequest";
				case LdapOperationType::ExtendedResponse:
					return "ExtendedResponse";
				case LdapOperationType::IntermediateResponse:
					return "IntermediateResponse";
				default:
					return "Unknown";
			}
		}

		static LdapOperationType fromIntValue(uint8_t value)
		{
			switch (value)
			{
				case static_cast<uint8_t>(LdapOperationType::BindRequest):
					return LdapOperationType::BindRequest;
				case static_cast<uint8_t>(LdapOperationType::BindResponse):
					return LdapOperationType::BindResponse;
				case static_cast<uint8_t>(LdapOperationType::UnbindRequest):
					return LdapOperationType::UnbindRequest;
				case static_cast<uint8_t>(LdapOperationType::SearchRequest):
					return LdapOperationType::SearchRequest;
				case static_cast<uint8_t>(LdapOperationType::SearchResultEntry):
					return LdapOperationType::SearchResultEntry;
				case static_cast<uint8_t>(LdapOperationType::SearchResultDone):
					return LdapOperationType::SearchResultDone;
				case static_cast<uint8_t>(LdapOperationType::ModifyResponse):
					return LdapOperationType::ModifyResponse;
				case static_cast<uint8_t>(LdapOperationType::AddRequest):
					return LdapOperationType::AddRequest;
				case static_cast<uint8_t>(LdapOperationType::AddResponse):
					return LdapOperationType::AddResponse;
				case static_cast<uint8_t>(LdapOperationType::DelRequest):
					return LdapOperationType::DelRequest;
				case static_cast<uint8_t>(LdapOperationType::DelResponse):
					return LdapOperationType::DelResponse;
				case static_cast<uint8_t>(LdapOperationType::ModifyDNRequest):
					return LdapOperationType::ModifyDNRequest;
				case static_cast<uint8_t>(LdapOperationType::ModifyDNResponse):
					return LdapOperationType::ModifyDNResponse;
				case static_cast<uint8_t>(LdapOperationType::CompareRequest):
					return LdapOperationType::CompareRequest;
				case static_cast<uint8_t>(LdapOperationType::CompareResponse):
					return LdapOperationType::CompareResponse;
				case static_cast<uint8_t>(LdapOperationType::AbandonRequest):
					return LdapOperationType::AbandonRequest;
				case static_cast<uint8_t>(LdapOperationType::SearchResultReference):
					return LdapOperationType::SearchResultReference;
				case static_cast<uint8_t>(LdapOperationType::ExtendedRequest):
					return LdapOperationType::ExtendedRequest;
				case static_cast<uint8_t>(LdapOperationType::ExtendedResponse):
					return LdapOperationType::ExtendedResponse;
				case static_cast<uint8_t>(LdapOperationType::IntermediateResponse):
					return LdapOperationType::IntermediateResponse;
				default:
					return LdapOperationType::Unknown;
			}
		}

	private:
		Value m_Value;
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
		class SearchRequestScope
		{
		public:
			enum Value : uint8_t
			{
				BaseObject = 0,
				SingleLevel = 1,
				WholeSubtree = 2,
				Unknown = 255
			};

			SearchRequestScope() = default;
			constexpr SearchRequestScope(Value value) : m_Value(value) {}
			constexpr operator Value() const { return m_Value; }

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;

			std::string toString() const
			{
				switch (m_Value)
				{
					case SearchRequestScope::BaseObject:
						return "BaseObject";
					case SearchRequestScope::SingleLevel:
						return "SingleLevel";
					case SearchRequestScope::WholeSubtree:
						return "WholeSubtree";
					default:
						return "Unknown";
				}
			}

			static SearchRequestScope fromIntValue(uint8_t value)
			{
				if (value >= 0 && value <= 2)
				{
					return static_cast<SearchRequestScope::Value>(value);
				}

				return SearchRequestScope::Unknown;
			}
		private:
			Value m_Value;
		};

		class DerefAliases
		{
		public:
			enum Value : uint8_t
			{
				NeverDerefAliases = 0,
				DerefInSearching = 1,
				DerefFindingBaseObj = 2,
				DerefAlways = 3,
				Unknown = 255
			};

			DerefAliases() = default;
			constexpr DerefAliases(Value value) : m_Value(value) {}
			constexpr operator Value() const { return m_Value; }

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;

			std::string toString() const
			{
				switch (m_Value)
				{
					case DerefAliases::NeverDerefAliases:
						return "NeverDerefAliases";
					case DerefAliases::DerefInSearching:
						return "DerefInSearching";
					case DerefAliases::DerefFindingBaseObj:
						return "DerefFindingBaseObj";
					case DerefAliases::DerefAlways:
						return "DerefAlways";
					default:
						return "Unknown";
				}
			}

			static DerefAliases fromIntValue(uint8_t value)
			{
				if (value >= 0 && value <= 3)
				{
					return static_cast<DerefAliases::Value>(value);
				}

				return DerefAliases::Unknown;
			}
		private:
			Value m_Value;
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
