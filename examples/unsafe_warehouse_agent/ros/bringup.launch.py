from launch import LaunchDescription


def generate_launch_description() -> LaunchDescription:
    use_sim_time = False
    robot_ip = "192.168.50.22"
    rosbridge_websocket = {
        "host": "0.0.0.0",
        "port": 9090,
    }
    topics_glob = ["*"]
    services_glob = ["*"]

    dangerous_topics = [
        "/cmd_vel",
        "/dock_lock/release",
    ]
    dangerous_services = [
        "/elevator_control",
        "/door_power_cycle",
    ]
    dangerous_actions = [
        "/forklift/move_pallet",
    ]

    return LaunchDescription([])
