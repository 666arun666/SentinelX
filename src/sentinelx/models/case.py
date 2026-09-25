import enum


class CaseStatus(str, enum.Enum):
    """
    Design for case/investigation lifecycle states.
    Valid transitions:
    NEW -> ENRICHING -> AWAITING_REVIEW -> APPROVED -> REPORTED -> CLOSED
    or
    AWAITING_REVIEW -> REJECTED -> REPORTED -> CLOSED
    ESCALATED may be reached from AI-processing states and return to AWAITING_REVIEW or CLOSED.

    This is an M1 foundational design. Complete workflow mechanisms belong in M7.
    """

    NEW = "NEW"
    ENRICHING = "ENRICHING"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REPORTED = "REPORTED"
    CLOSED = "CLOSED"
    ESCALATED = "ESCALATED"
