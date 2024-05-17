#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <ostream>
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

	class LdapResultCode
	{
	public:
		enum Value : uint8_t
		{
			Success = 0,
			OperationsError= 1,
			ProtocolError = 2,
			TimeLimitExceeded = 3,
			SizeLimitExceeded = 4,
			CompareFalse = 5,
			CompareTrue = 6,
			AuthMethodNotSupported = 7,
			StrongerAuthRequired = 8,
			// 9 reserved
			Referral = 10,
			AdminLimitExceeded = 11,
			UnavailableCriticalExtension = 12,
			ConfidentialityRequired = 13,
			SaslBindInProgress = 14,
			NoSuchAttribute = 16,
			UndefinedAttributeType = 17,
			InappropriateMatching = 18,
			ConstraintViolation = 19,
			AttributeOrValueExists = 20,
			InvalidAttributeSyntax = 21,
			// 22-31 unused
			NoSuchObject = 32,
			AliasProblem = 33,
			InvalidDNSyntax = 34,
			// 35 reserved for undefined isLeaf
			AliasDereferencingProblem = 36,
			// 37-47 unused
			InappropriateAuthentication = 48,
			InvalidCredentials = 49,
			InsufficientAccessRights = 50,
			Busy = 51,
			Unavailable = 52,
			UnwillingToPerform = 53,
			LoopDetect = 54,
			// 55-63 unused
			NamingViolation = 64,
			ObjectClassViolation = 65,
			NotAllowedOnNonLeaf = 66,
			NotAllowedOnRDN = 67,
			EntryAlreadyExists = 68,
			ObjectClassModsProhibited = 69,
			// 70 reserved for CLDAP
			AffectsMultipleDSAs = 71,
			// 72-79 unused
			Other = 80,
			Unknown = 255
		};

		LdapResultCode() = default;
		constexpr LdapResultCode(Value value) : m_Value(value) { }
		constexpr operator Value() const { return m_Value; }

		// Prevent usage: if(LdapResultCode)
		explicit operator bool() const = delete;

		std::string toString() const
		{
			switch (m_Value)
			{
				case LdapResultCode::Success:
					return "Success";
				case LdapResultCode::OperationsError:
					return "OperationsError";
				case LdapResultCode::ProtocolError:
					return "ProtocolError";
				case LdapResultCode::TimeLimitExceeded:
					return "TimeLimitExceeded";
				case LdapResultCode::SizeLimitExceeded:
					return "SizeLimitExceeded";
				case LdapResultCode::CompareFalse:
					return "CompareFalse";
				case LdapResultCode::CompareTrue:
					return "CompareTrue";
				case LdapResultCode::AuthMethodNotSupported:
					return "AuthMethodNotSupported";
				case LdapResultCode::StrongerAuthRequired:
					return "StrongerAuthRequired";
				case LdapResultCode::Referral:
					return "Referral";
				case LdapResultCode::AdminLimitExceeded:
					return "AdminLimitExceeded";
				case LdapResultCode::UnavailableCriticalExtension:
					return "UnavailableCriticalExtension";
				case LdapResultCode::ConfidentialityRequired:
					return "ConfidentialityRequired";
				case LdapResultCode::SaslBindInProgress:
					return "SaslBindInProgress";
				case LdapResultCode::NoSuchAttribute:
					return "NoSuchAttribute";
				case LdapResultCode::UndefinedAttributeType:
					return "UndefinedAttributeType";
				case LdapResultCode::InappropriateMatching:
					return "InappropriateMatching";
				case LdapResultCode::ConstraintViolation:
					return "ConstraintViolation";
				case LdapResultCode::AttributeOrValueExists:
					return "AttributeOrValueExists";
				case LdapResultCode::InvalidAttributeSyntax:
					return "InvalidAttributeSyntax";
				case LdapResultCode::NoSuchObject:
					return "NoSuchObject";
				case LdapResultCode::AliasProblem:
					return "AliasProblem";
				case LdapResultCode::InvalidDNSyntax:
					return "InvalidDNSyntax";
				case LdapResultCode::AliasDereferencingProblem:
					return "AliasDereferencingProblem";
				case LdapResultCode::InappropriateAuthentication:
					return "InappropriateAuthentication";
				case LdapResultCode::InvalidCredentials:
					return "InvalidCredentials";
				case LdapResultCode::InsufficientAccessRights:
					return "InsufficientAccessRights";
				case LdapResultCode::Busy:
					return "Busy";
				case LdapResultCode::Unavailable:
					return "Unavailable";
				case LdapResultCode::UnwillingToPerform:
					return "UnwillingToPerform";
				case LdapResultCode::LoopDetect:
					return "LoopDetect";
				case LdapResultCode::NamingViolation:
					return "NamingViolation";
				case LdapResultCode::ObjectClassViolation:
					return "ObjectClassViolation";
				case LdapResultCode::NotAllowedOnNonLeaf:
					return "NotAllowedOnNonLeaf";
				case LdapResultCode::NotAllowedOnRDN:
					return "NotAllowedOnRDN";
				case LdapResultCode::EntryAlreadyExists:
					return "EntryAlreadyExists";
				case LdapResultCode::ObjectClassModsProhibited:
					return "ObjectClassModsProhibited";
				case LdapResultCode::AffectsMultipleDSAs:
					return "AffectsMultipleDSAs";
				case LdapResultCode::Other:
					return "Other";
				default:
					return "Unknown";
			}
		}

		static LdapResultCode fromIntValue(uint8_t value)
		{
			switch (value)
			{
				case static_cast<uint8_t>(LdapResultCode::Success):
					return LdapResultCode::Success;
				case static_cast<uint8_t>(LdapResultCode::OperationsError):
					return LdapResultCode::OperationsError;
				case static_cast<uint8_t>(LdapResultCode::ProtocolError):
					return LdapResultCode::ProtocolError;
				case static_cast<uint8_t>(LdapResultCode::TimeLimitExceeded):
					return LdapResultCode::TimeLimitExceeded;
				case static_cast<uint8_t>(LdapResultCode::SizeLimitExceeded):
					return LdapResultCode::SizeLimitExceeded;
				case static_cast<uint8_t>(LdapResultCode::CompareFalse):
					return LdapResultCode::CompareFalse;
				case static_cast<uint8_t>(LdapResultCode::CompareTrue):
					return LdapResultCode::CompareTrue;
				case static_cast<uint8_t>(LdapResultCode::AuthMethodNotSupported):
					return LdapResultCode::AuthMethodNotSupported;
				case static_cast<uint8_t>(LdapResultCode::StrongerAuthRequired):
					return LdapResultCode::StrongerAuthRequired;
				case static_cast<uint8_t>(LdapResultCode::Referral):
					return LdapResultCode::Referral;
				case static_cast<uint8_t>(LdapResultCode::AdminLimitExceeded):
					return LdapResultCode::AdminLimitExceeded;
				case static_cast<uint8_t>(LdapResultCode::UnavailableCriticalExtension):
					return LdapResultCode::UnavailableCriticalExtension;
				case static_cast<uint8_t>(LdapResultCode::ConfidentialityRequired):
					return LdapResultCode::ConfidentialityRequired;
				case static_cast<uint8_t>(LdapResultCode::SaslBindInProgress):
					return LdapResultCode::SaslBindInProgress;
				case static_cast<uint8_t>(LdapResultCode::NoSuchAttribute):
					return LdapResultCode::NoSuchAttribute;
				case static_cast<uint8_t>(LdapResultCode::UndefinedAttributeType):
					return LdapResultCode::UndefinedAttributeType;
				case static_cast<uint8_t>(LdapResultCode::InappropriateMatching):
					return LdapResultCode::InappropriateMatching;
				case static_cast<uint8_t>(LdapResultCode::ConstraintViolation):
					return LdapResultCode::ConstraintViolation;
				case static_cast<uint8_t>(LdapResultCode::AttributeOrValueExists):
					return LdapResultCode::AttributeOrValueExists;
				case static_cast<uint8_t>(LdapResultCode::InvalidAttributeSyntax):
					return LdapResultCode::InvalidAttributeSyntax;
				case static_cast<uint8_t>(LdapResultCode::NoSuchObject):
					return LdapResultCode::NoSuchObject;
				case static_cast<uint8_t>(LdapResultCode::AliasProblem):
					return LdapResultCode::AliasProblem;
				case static_cast<uint8_t>(LdapResultCode::InvalidDNSyntax):
					return LdapResultCode::InvalidDNSyntax;
				case static_cast<uint8_t>(LdapResultCode::AliasDereferencingProblem):
					return LdapResultCode::AliasDereferencingProblem;
				case static_cast<uint8_t>(LdapResultCode::InappropriateAuthentication):
					return LdapResultCode::InappropriateAuthentication;
				case static_cast<uint8_t>(LdapResultCode::InvalidCredentials):
					return LdapResultCode::InvalidCredentials;
				case static_cast<uint8_t>(LdapResultCode::InsufficientAccessRights):
					return LdapResultCode::InsufficientAccessRights;
				case static_cast<uint8_t>(LdapResultCode::Busy):
					return LdapResultCode::Busy;
				case static_cast<uint8_t>(LdapResultCode::Unavailable):
					return LdapResultCode::Unavailable;
				case static_cast<uint8_t>(LdapResultCode::UnwillingToPerform):
					return LdapResultCode::UnwillingToPerform;
				case static_cast<uint8_t>(LdapResultCode::LoopDetect):
					return LdapResultCode::LoopDetect;
				case static_cast<uint8_t>(LdapResultCode::NamingViolation):
					return LdapResultCode::NamingViolation;
				case static_cast<uint8_t>(LdapResultCode::ObjectClassViolation):
					return LdapResultCode::ObjectClassViolation;
				case static_cast<uint8_t>(LdapResultCode::NotAllowedOnNonLeaf):
					return LdapResultCode::NotAllowedOnNonLeaf;
				case static_cast<uint8_t>(LdapResultCode::NotAllowedOnRDN):
					return LdapResultCode::NotAllowedOnRDN;
				case static_cast<uint8_t>(LdapResultCode::EntryAlreadyExists):
					return LdapResultCode::EntryAlreadyExists;
				case static_cast<uint8_t>(LdapResultCode::ObjectClassModsProhibited):
					return LdapResultCode::ObjectClassModsProhibited;
				case static_cast<uint8_t>(LdapResultCode::AffectsMultipleDSAs):
					return LdapResultCode::AffectsMultipleDSAs;
				case static_cast<uint8_t>(LdapResultCode::Other):
					return LdapResultCode::Other;
				default:
					return LdapResultCode::Unknown;
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
		LdapLayer() = default;
		void init(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords);
		Asn1SequenceRecord* getAsn1Record() const;
		Asn1ConstructedRecord* getMessageRecord() const;
		virtual std::string getExtendedStringInfo() const {return ""; }

		template <typename T, typename Member, typename LdapClass>
		bool internalTryGet(LdapClass* thisPtr, Member member, T& result)
		{
			try
			{
				result = (thisPtr->*member)();
				return true;
			}
			catch (...)
			{
				return false;
			}
		}
	};

	struct LdapPartialAttribute
	{
		std::string type;
		std::vector<std::string> values;

		bool operator==(const LdapPartialAttribute& other) const
		{
			return type == other.type && values == other.values;
		}
	};

	struct LdapResult
	{
		LdapResultCode resultCode;
		std::string matchedDN;
		std::string diagnosticMessage;
		std::string referral;

		bool operator==(const LdapResult& other) const
		{
			return resultCode == other.resultCode && matchedDN == other.matchedDN && diagnosticMessage == other.diagnosticMessage && referral == other.referral;
		}
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

		LdapSearchRequestLayer(
				uint16_t messageId, const std::string& baseObject, SearchRequestScope scope, DerefAliases derefAliases,
				uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly, const std::vector<uint8_t>& filter,
				const std::vector<std::string>& attributes);
		std::string getBaseObject() const;
		SearchRequestScope getScope() const;
		DerefAliases getDerefAlias() const;
		uint8_t getSizeLimit() const;
		uint8_t getTimeLimit() const;
		bool getTypesOnly() const;
		// TODO: std::string getFilter();
		std::vector<std::string> getAttributes() const;

		template <typename T, typename Member>
		bool tryGet(Member member, T& result)
		{
			return internalTryGet(this, member, result);
		}

	protected:
		std::string getExtendedStringInfo() const override;
	};

	class LdapSearchResultEntryLayer : public LdapLayer
	{
	public:
		LdapSearchResultEntryLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: LdapLayer(asn1Record, data, dataLen, prevLayer, packet) {}

		LdapSearchResultEntryLayer(uint16_t messageId, const std::string& objectName, const std::vector<LdapPartialAttribute>& attributes);

		std::string getObjectName() const;
		std::vector<LdapPartialAttribute> getAttributes() const;

		template <typename T, typename Member>
		bool tryGet(Member member, T& result)
		{
			return internalTryGet(this, member, result);
		}
	};

	class LdapSearchResultDoneLayer : public LdapLayer
	{
	public:
		LdapSearchResultDoneLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: LdapLayer(asn1Record, data, dataLen, prevLayer, packet) {}

		LdapSearchResultDoneLayer(uint16_t messageId, const LdapResultCode& resultCode, const std::string& matchedDN,
			const std::string& diagnosticMessage, const std::string& referral = "");

		LdapResult getResult() const;

		template <typename T, typename Member>
		bool tryGet(Member member, T& result)
		{
			return internalTryGet(this, member, result);
		}
	};
} // namespace pcpp

inline std::ostream& operator<<(std::ostream& os, const pcpp::LdapPartialAttribute& attr)
{
	std::string valuesStream;
	bool first = true;
	for (const auto& value : attr.values)
	{
		if (!first) valuesStream += ", ";
		valuesStream += value;
		first = false;
	}
	os << "{" << attr.type << ", {" << valuesStream << "}}";
	return os;
}
