def create_flow_status(operation_status: int, core_status: int) -> int:
    CORE_STATUS_MASK = 0xFF
    CORE_STATUS_SHIFT = 8
    APP_STATUS_MASK = 0xFF
    APP_STATUS_SHIFT = 0

    flow_status = 0
    flow_status |= (core_status & CORE_STATUS_MASK) << CORE_STATUS_SHIFT
    flow_status |= (operation_status & APP_STATUS_MASK) << APP_STATUS_SHIFT

    return flow_status
