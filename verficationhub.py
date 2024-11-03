import streamlit as st
from datetime import datetime, timedelta
import uuid
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, EmailStr, validator
import requests
from dataclasses import dataclass
import logging
from dataclasses import dataclass, field
from email_validator import validate_email, EmailNotValidError
import random
import string

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# New Error Code Enum
class VerificationErrorCode(str, Enum):
    NOT_FOUND = "NOT_FOUND"
    EXPIRED = "EXPIRED"
    INVALID_OTP = "INVALID_OTP"
    INVALID_REQUEST = "INVALID_REQUEST"
    CHANNEL_ERROR = "CHANNEL_ERROR"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INVALID_CONTACT = "INVALID_CONTACT"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    UNAUTHORIZED = "UNAUTHORIZED"
    VALIDATION_ERROR = "VALIDATION_ERROR"

# Custom Exception Class
class VerificationError(Exception):
    def __init__(
        self,
        code: VerificationErrorCode,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ):
        self.code = code
        self.message = message
        self.details = details or {}
        self.timestamp = timestamp or datetime.utcnow()
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class Settings:
    """Application settings with type hints and documentation."""
    TNID_API_URL: str = ""https://api.staging.v2.tnid.com/auth/create_user_otp"
    COMPANY_ID: str = "477f21dd-77c9-44e9-929e-47c2e9a0609e"
    DEFAULT_RATE_LIMITS: Dict[str, int] = field(default_factory=lambda: {
        "requestsPerMinute": 60,
        "requestsPerHour": 1000,
        "requestsPerDay": 10000
    })
    API_TIMEOUT: int = 30  # seconds
    OTP_LENGTH: int = 6
    OTP_EXPIRY: int = 300  # 5 minutes

class ChannelType(str, Enum):
    SMS = "SMS"
    VOICE = "VOICE"
    EMAIL = "EMAIL"
    WHATSAPP = "WHATSAPP"
    TELEGRAM = "TELEGRAM"
    OTP = "OTP"

class VerificationType(str, Enum):
    TWO_FACTOR = "TWO_FACTOR"
    IDENTITY = "IDENTITY"
    AGE = "AGE"
    ADDRESS = "ADDRESS"
    DOCUMENT = "DOCUMENT"
    BIOMETRIC = "BIOMETRIC"
    OTP = "OTP"

class Status(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

# Error handling utility function
def handle_verification_error(error: Exception) -> Dict[str, Any]:
    """Convert various errors to a standardized error response format."""
    if isinstance(error, VerificationError):
        logger.error(f"Verification error: {error.code} - {error.message}")
        return error.to_dict()
    
    if isinstance(error, KeyError):
        return VerificationError(
            code=VerificationErrorCode.NOT_FOUND,
            message="Requested verification not found",
            details={"error_type": "KeyError"}
        ).to_dict()
    elif isinstance(error, ValueError):
        return VerificationError(
            code=VerificationErrorCode.VALIDATION_ERROR,
            message=str(error),
            details={"error_type": "ValueError"}
        ).to_dict()
    
    logger.exception("Unexpected error in verification process")
    return VerificationError(
        code=VerificationErrorCode.SYSTEM_ERROR,
        message="An unexpected error occurred",
        details={"original_error": str(error)}
    ).to_dict()

class VerificationRequest(BaseModel):
    company_id: str = Field(..., description="Unique identifier for the company")
    channel: ChannelType
    contact_info: str = Field(..., min_length=1)
    verification_type: VerificationType
    metadata: Dict[str, Any] = Field(default_factory=dict)
    expires_in: int = Field(default=3600, ge=60, le=86400)
    otp_code: Optional[str] = None

    @validator('contact_info')
    def validate_contact_info(cls, v, values):
        try:
            channel = values.get('channel')
            if channel == ChannelType.EMAIL:
                email_info = validate_email(v, check_deliverability=False)
                return email_info.normalized
            elif channel == ChannelType.SMS:
                if not v.startswith('+'):
                    raise ValueError('Phone numbers must start with + and country code')
            return v
        except EmailNotValidError as e:
            raise VerificationError(
                code=VerificationErrorCode.INVALID_CONTACT,
                message=str(e),
                details={"contact_info": v, "channel": values.get('channel')}
            )

class VerificationResponse(BaseModel):
    request_id: str
    status: Status
    timestamp: datetime
    channel: ChannelType
    verified: bool
    error: Optional[Dict[str, Any]] = None
    verification_data: Optional[Dict[str, Any]] = None

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
class VerificationService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.verifications: Dict[str, Dict[str, Any]] = {}
        self._session = requests.Session()
        self.otps: Dict[str, Dict[str, Any]] = {}

    def generate_otp(self) -> str:
        """Generate a random OTP code."""
        return ''.join(random.choices(string.digits, k=self.settings.OTP_LENGTH))

    def verify_otp(self, request_id: str, otp_code: str) -> bool:
        """Verify the OTP code for a given request."""
        try:
            verification = self.verifications.get(request_id)
            if not verification:
                raise VerificationError(
                    code=VerificationErrorCode.NOT_FOUND,
                    message="Verification not found",
                    details={"request_id": request_id}
                )
            
            stored_otp = verification.get('otp_code')
            if not stored_otp:
                raise VerificationError(
                    code=VerificationErrorCode.INVALID_OTP,
                    message="No OTP associated with this verification",
                    details={"request_id": request_id}
                )
            
            return stored_otp == otp_code
        except Exception as e:
            logger.error(f"OTP verification failed: {str(e)}")
            return False

    def initiate_verification(self, request: VerificationRequest) -> VerificationResponse:
        """Initiate a new verification request with OTP generation."""
        try:
            request_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            otp_supported_channels = [
                ChannelType.SMS, 
                ChannelType.EMAIL, 
                ChannelType.WHATSAPP, 
                ChannelType.TELEGRAM, 
            ]
            
            otp_code = None
            if request.channel in otp_supported_channels:
                otp_code = self.generate_otp()
                logger.info(f"Generated OTP for {request.channel}: {otp_code}")
                print(f"Generated OTP for {request.channel}: {otp_code}")
            
            verification_data = {
                "status": Status.PENDING.value,
                "channel": request.channel.value,
                "created_at": timestamp.isoformat(),
                "company_id": request.company_id,
                "contact_info": request.contact_info,
                "verification_type": request.verification_type.value,
                "metadata": request.metadata,
                "expires_at": (timestamp + timedelta(seconds=request.expires_in)).isoformat(),
                "otp_code": otp_code
            }
            
            self.verifications[request_id] = verification_data
            
            return VerificationResponse(
                request_id=request_id,
                status=Status.PENDING,
                timestamp=timestamp,
                channel=request.channel,
                verified=False,
                verification_data={"otp_code": otp_code} if otp_code else None
            )
        except Exception as e:
            error_dict = handle_verification_error(e)
            return VerificationResponse(
                request_id=str(uuid.uuid4()),
                status=Status.FAILED,
                timestamp=datetime.utcnow(),
                channel=request.channel,
                verified=False,
                error=error_dict
            )

    def check_status(self, request_id: str, otp_code: Optional[str] = None) -> VerificationResponse:
        """Simplified status check that always returns verified."""
        try:
            verification = self.verifications.get(request_id)
            if not verification:
                raise VerificationError(
                    code=VerificationErrorCode.NOT_FOUND,
                    message=f"Verification with ID {request_id} not found",
                    details={"request_id": request_id}
                )

            # Always set as verified
            verification["status"] = Status.COMPLETED.value
            verification["verified"] = True
            verification["updated_at"] = datetime.utcnow().isoformat()
            
            return VerificationResponse(
                request_id=request_id,
                status=Status.COMPLETED,
                timestamp=datetime.utcnow(),
                channel=ChannelType(verification["channel"]),
                verified=True,
                verification_data={"message": "ID Verified"}
            )

        except Exception as e:
            error_dict = handle_verification_error(e)
            logger.error(f"Unexpected error in check_status: {str(e)}")
            return VerificationResponse(
                request_id=request_id,
                status=Status.FAILED,
                timestamp=datetime.utcnow(),
                channel=ChannelType.SMS,
                verified=False,
                error=error_dict
            )
        
def check_status(self, request_id: str, otp_code: Optional[str] = None) -> VerificationResponse:
        """Simplified status check that always returns verified."""
        try:
            verification = self.verifications.get(request_id)
            if not verification:
                raise VerificationError(
                    code=VerificationErrorCode.NOT_FOUND,
                    message=f"Verification with ID {request_id} not found",
                    details={"request_id": request_id}
                )

            # Always set as verified
            verification["status"] = Status.COMPLETED.value
            verification["verified"] = True
            verification["updated_at"] = datetime.utcnow().isoformat()
            
            return VerificationResponse(
                request_id=request_id,
                status=Status.COMPLETED,
                timestamp=datetime.utcnow(),
                channel=ChannelType(verification["channel"]),
                verified=True,
                verification_data={"message": "ID Verified"}
            )

        except Exception as e:
            error_dict = handle_verification_error(e)
            logger.error(f"Unexpected error in check_status: {str(e)}")
            return VerificationResponse(
                request_id=request_id,
                status=Status.FAILED,
                timestamp=datetime.utcnow(),
                channel=ChannelType.SMS,
                verified=False,
                error=error_dict
            )

def main():
    """Main Streamlit application with OTP support."""
    st.set_page_config(page_title="Multi-Channel Verification Hub", page_icon="🔒")
    st.title("Multi-Channel Verification Hub")
    
    if 'verifications' not in st.session_state:
        st.session_state.verifications = {}
    if 'current_verification' not in st.session_state:
        st.session_state.current_verification = None
    
    settings = Settings()
    service = VerificationService(settings)

    with st.form("verification_form", clear_on_submit=False):
        col1, col2 = st.columns(2)
        
        with col1:
            company_id = st.text_input(
                "Company ID",
                value=settings.COMPANY_ID,
                help="Unique identifier for your company"
            )
            channel = st.selectbox(
                "Channel",
                options=[e.value for e in ChannelType],
                help="Select the verification channel",
                key="selected_channel"
            )
            
        with col2:
            contact_info = st.text_input(
                "Contact Information",
                help="Email address or phone number with country code (+)",
                key="contact_info"
            )
            verification_type = st.selectbox(
                "Verification Type",
                options=[e.value for e in VerificationType],
                help="Select the type of verification needed",
                key="verification_type"
            )
        
        submit_button = st.form_submit_button("Start Verification")

        if submit_button:
            try:
                if not contact_info:
                    raise VerificationError(
                        code=VerificationErrorCode.INVALID_REQUEST,
                        message="Please enter contact information"
                    )

                request = VerificationRequest(
                    company_id=company_id,
                    channel=ChannelType(channel),
                    contact_info=contact_info,
                    verification_type=VerificationType(verification_type),
                    metadata={},
                    expires_in=3600
                )
                
                response = service.initiate_verification(request)
                
                if response.error:
                    st.error(f"❌ {response.error['message']}")
                    if 'details' in response.error:
                        with st.expander("Error Details"):
                            st.json(response.error['details'])
                else:
                    st.session_state.current_verification = {
                        'request_id': response.request_id,
                        'channel': channel,
                        'contact_info': contact_info,
                        'verification_type': verification_type,
                        'requires_otp': channel in ['SMS', 'EMAIL', 'WHATSAPP', 'TELEGRAM', 'OTP']
                    }
                    st.success(f"✅ Verification initiated! Request ID: {response.request_id}")
                    
                    if response.verification_data and "otp_code" in response.verification_data:
                        st.info(f"🔑 Test OTP Code: {response.verification_data['otp_code']}")
                    
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

    # Status Check Section
    if st.session_state.current_verification:
        st.divider()
        st.subheader("Verification Status")
        
        # Display current verification details
        with st.expander("Current Verification Details", expanded=True):
            st.json({
                "Request ID": st.session_state.current_verification['request_id'],
                "Channel": st.session_state.current_verification['channel'],
                "Contact Info": st.session_state.current_verification['contact_info'],
                "Type": st.session_state.current_verification['verification_type']
            })
        
        # Add OTP input field for supported channels
        otp_code = None
        if st.session_state.current_verification.get('requires_otp', False):
            otp_code = st.text_input(
                "Enter OTP Code", 
                max_chars=6, 
                key="otp_input",
                help="Enter the OTP code you received"
            )
        
        col1, col2 = st.columns([1, 3])
        with col1:
            verify_button = st.button("Verify Status", type="primary", key="check_status")
        with col2:
            clear_button = st.button("Start New Verification", key="clear_verification")

        if verify_button:
            # Display verification success
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(
                    "Status",
                    "COMPLETED",
                    delta="Verified",
                    delta_color="normal"
                )
            with col2:
                st.metric(
                    "Verification",
                    "ID Verified",
                    delta="Success"
                )
            with col3:
                timestamp = datetime.utcnow().strftime("%H:%M:%S")
                st.metric("Timestamp", timestamp)
            
            st.success("✅ ID Verified Successfully!")

            # Display OTP verification if applicable
            if st.session_state.current_verification.get('requires_otp', False):
                if otp_code:
                    st.info(f"OTP Code Received: {otp_code}")

        if clear_button:
            st.session_state.current_verification = None
            st.experimental_rerun()

if __name__ == "__main__":
    main()
