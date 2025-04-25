#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/twai.h" // ESP32 CAN interface
#include "canard.h"

#define TAG "UAVCAN_NODE"

// Manual definitions for NodeStatus
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_FIXED_PORT_ID 341 // Fixed port ID for NodeStatus
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_MAX_SIZE 7        // Maximum serialized size of NodeStatus
#define UAVCAN_PROTOCOL_NODESTATUS_SIGNATURE 0x013493d7225e45b9ULL // Data type signature for NodeStatus

// Health states
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_HEALTH_OK 0
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_HEALTH_WARNING 1
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_HEALTH_ERROR 2
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_HEALTH_CRITICAL 3

// Operational modes
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_MODE_INITIALIZATION 0
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_MODE_MAINTENANCE 1
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_MODE_OPERATIONAL 2
#define UAVCAN_PROTOCOL_NODESTATUS_1_0_MODE_SOFTWARE_UPDATE 3

// NodeStatus structure
typedef struct {
    uint32_t uptime_sec;
    uint8_t health;
    uint8_t mode;
    uint8_t sub_mode;
    uint16_t vendor_specific_status_code;
} uavcan_protocol_NodeStatus_1_0;

// Encode function (manual implementation)
static uint32_t uavcan_protocol_NodeStatus_1_0_encode(const uavcan_protocol_NodeStatus_1_0 *msg, uint8_t *buffer) {
    buffer[0] = (msg->uptime_sec >> 0) & 0xFF;
    buffer[1] = (msg->uptime_sec >> 8) & 0xFF;
    buffer[2] = (msg->uptime_sec >> 16) & 0xFF;
    buffer[3] = (msg->uptime_sec >> 24) & 0xFF;
    buffer[4] = msg->health;
    buffer[5] = msg->mode;
    buffer[6] = msg->sub_mode;
    return 7; // Always 7 bytes for this message
}

// Decode function (manual implementation)
static void uavcan_protocol_NodeStatus_1_0_decode(const uint8_t *buffer, uavcan_protocol_NodeStatus_1_0 *msg) {
    msg->uptime_sec = (buffer[0] << 0) | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
    msg->health = buffer[4];
    msg->mode = buffer[5];
    msg->sub_mode = buffer[6];
    msg->vendor_specific_status_code = 0; // Not part of the serialized payload
}

// Libcanard instance and memory pool
static CanardInstance canard;
static uint8_t memory_pool[1024];

// CAN bus configuration
#define CAN_TX_PIN GPIO_NUM_4 // GPIO for TX
#define CAN_RX_PIN GPIO_NUM_5 // GPIO for RX
#define MY_NODE_ID 97         // Set your node ID here

// Node status variable
static uavcan_protocol_NodeStatus_1_0 node_status;

// Initialize the CAN bus (TWAI for ESP32)
void initCAN() {
    twai_general_config_t g_config = TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX_PIN, CAN_RX_PIN, TWAI_MODE_NO_ACK); // No ACK mode for loopback
    twai_timing_config_t t_config = TWAI_TIMING_CONFIG_500KBITS(); // 500 kbps
    twai_filter_config_t f_config = TWAI_FILTER_CONFIG_ACCEPT_ALL();

    if (twai_driver_install(&g_config, &t_config, &f_config) == ESP_OK) {
        ESP_LOGI(TAG, "CAN driver installed");
    } else {
        ESP_LOGE(TAG, "Failed to install CAN driver");
        return;
    }

    if (twai_start() == ESP_OK) {
        ESP_LOGI(TAG, "CAN driver started");
    } else {
        ESP_LOGE(TAG, "Failed to start CAN driver");
    }
}

// Get monotonic timestamp in microseconds
static uint64_t micros64(void) {
    return esp_timer_get_time(); // Use ESP32's high-resolution timer
}

// Send NodeStatus message at 1Hz
void sendNodeStatus(void) {
    uint8_t buffer[UAVCAN_PROTOCOL_NODESTATUS_1_0_MAX_SIZE];

    // Set NodeStatus values
    node_status.uptime_sec = micros64() / 1000000ULL;
    node_status.health = UAVCAN_PROTOCOL_NODESTATUS_1_0_HEALTH_OK;
    node_status.mode = UAVCAN_PROTOCOL_NODESTATUS_1_0_MODE_OPERATIONAL;
    node_status.sub_mode = 0;
    node_status.vendor_specific_status_code = 0; // Follow DroneCAN standard

    // Encode the NodeStatus message
    uint32_t len = uavcan_protocol_NodeStatus_1_0_encode(&node_status, buffer);

    // Broadcast the NodeStatus message on the CAN bus
    static uint8_t transfer_id = 0; // Transfer ID managed by Libcanard
    int16_t result = canardBroadcast(
        &canard,                                // Library instance
        UAVCAN_PROTOCOL_NODESTATUS_SIGNATURE,  // Data type signature
        UAVCAN_PROTOCOL_NODESTATUS_1_0_FIXED_PORT_ID, // Data type ID
        &transfer_id,                           // Pointer to transfer ID
        CANARD_TRANSFER_PRIORITY_LOW,          // Transfer priority
        buffer,                                 // Payload buffer
        len                                     // Payload length in bytes
    );

    if (result >= 0) {
        ESP_LOGI(TAG, "NodeStatus message broadcasted");
    } else {
        ESP_LOGE(TAG, "Failed to broadcast NodeStatus message");
    }
}

// This callback handles received transfers
static void onTransferReceived(CanardInstance *ins, CanardRxTransfer *transfer) {
    // Check if the received message is a NodeStatus message
    if (transfer->data_type_id == UAVCAN_PROTOCOL_NODESTATUS_1_0_FIXED_PORT_ID) {
        uavcan_protocol_NodeStatus_1_0 received_status;

        // Ensure the payload length matches the expected size
        if (transfer->payload_len != UAVCAN_PROTOCOL_NODESTATUS_1_0_MAX_SIZE) {
            ESP_LOGE(TAG, "Invalid payload length for NodeStatus message");
            return;
        }

        // Access the payload data from the transfer
        const uint8_t *payload_buffer = transfer->payload_head; // Use payload_head for single-frame transfers

        // Decode the received NodeStatus message
        uavcan_protocol_NodeStatus_1_0_decode(payload_buffer, &received_status);

        // Print the received NodeStatus message
        ESP_LOGI(TAG, "Received NodeStatus message:");
        ESP_LOGI(TAG, "  Uptime: %lu", received_status.uptime_sec);
        ESP_LOGI(TAG, "  Health: %u", received_status.health);
        ESP_LOGI(TAG, "  Mode: %u", received_status.mode);
        ESP_LOGI(TAG, "  Sub-mode: %u", received_status.sub_mode);
    }
}

// This callback determines if we should accept a transfer
static bool shouldAcceptTransfer(const CanardInstance *ins,
                                  uint64_t *out_data_type_signature,
                                  uint16_t data_type_id,
                                  CanardTransferType transfer_type,
                                  uint8_t source_node_id) {
    // Accept all transfers for simplicity
    if (data_type_id == UAVCAN_PROTOCOL_NODESTATUS_1_0_FIXED_PORT_ID) {
        *out_data_type_signature = UAVCAN_PROTOCOL_NODESTATUS_SIGNATURE;
        return true;
    }
    return false;
}

void app_main() {
    // Initialize logging
    esp_log_level_set("*", ESP_LOG_INFO);

    // Initialize CAN (TWAI)
    initCAN();

    // Initialize Libcanard
    canardInit(&canard,
               memory_pool,
               sizeof(memory_pool),
               onTransferReceived,
               shouldAcceptTransfer,
               NULL);

    // Set local node ID
    canardSetLocalNodeID(&canard, MY_NODE_ID);

    ESP_LOGI(TAG, "Node initialized");

    // Main loop
    static uint64_t next_1hz_service_at = 0;
     next_1hz_service_at = micros64();
    while (1) {
        // Transmit NodeStatus at 1Hz
        uint64_t ts = micros64();
        if (ts >= next_1hz_service_at) {
            next_1hz_service_at += 1000000ULL; // 1 second
            sendNodeStatus();
        }

        // Manually handle CAN frame transmission
        const CanardCANFrame* tx_frame = canardPeekTxQueue(&canard);
        if (tx_frame != NULL) {
            twai_message_t tx_msg;
            tx_msg.identifier = tx_frame->id;
            tx_msg.data_length_code = tx_frame->data_len;
            memcpy(tx_msg.data, tx_frame->data, tx_frame->data_len);

            if (twai_transmit(&tx_msg, pdMS_TO_TICKS(10)) == ESP_OK) {
                // Frame transmitted successfully
                canardPopTxQueue(&canard); // Remove the frame from Libcanard's TX queue
            } else {
                ESP_LOGE(TAG, "Failed to transmit CAN frame");
            }
        }

        // Receive and handle CAN messages
        twai_message_t rx_frame;
        if (twai_receive(&rx_frame, pdMS_TO_TICKS(10)) == ESP_OK) { // Timeout 10ms
            // Process received frame
            CanardCANFrame frame;
            frame.id = rx_frame.identifier;
            memcpy(frame.data, rx_frame.data, rx_frame.data_length_code);
            frame.data_len = rx_frame.data_length_code; // Correct field name
            uint64_t timestamp = micros64();
            canardHandleRxFrame(&canard, &frame, timestamp);
        }
    }
}