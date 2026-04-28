from __future__ import annotations

import re
from pathlib import Path

from lily_sweep.models import Finding, ROSPolicy
from lily_sweep.scanners.base import Scanner

ROS_HINTS = (
    "rclpy",
    "rclcpp",
    "rosbridge",
    "ros2_control",
    "create_publisher",
    "create_client",
    "actionclient",
    "send_goal",
    "use_sim_time",
    "gazebo",
    "moveit",
)

DEFAULT_DANGEROUS_TOPICS = (
    "/cmd_vel",
    "cmd_vel",
    "/joint_trajectory",
    "joint_trajectory",
    "/gripper_command",
    "/door_unlock",
    "/elevator_control",
    "/arm_controller",
)

DEFAULT_DANGEROUS_SERVICES = (
    "/elevator_control",
    "/door_unlock",
    "/power_on_motors",
    "/release_brake",
    "/set_operating_mode",
)

DEFAULT_DANGEROUS_ACTIONS = (
    "/follow_joint_trajectory",
    "/move_arm",
    "/navigate_to_pose",
    "/forklift/move_pallet",
)

HARDWARE_HINTS = (
    "robot_ip",
    "hardware_interface",
    "real_robot",
    "serial_port",
    "can_bus",
    "ethercat",
    "production_robot",
)

SIM_HINTS = (
    "use_sim_time",
    "gazebo",
    "simulation",
    "fake_hardware",
)

REMOTE_EXPOSURE_HINTS = (
    "rosbridge_websocket",
    "websocket",
    "0.0.0.0",
    "9090",
)

ROS_FILE_SUFFIXES = {
    ".py",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hh",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".xml",
}


class RosControlScanner(Scanner):
    name = "ros_control"

    def __init__(self, policy: ROSPolicy | None = None) -> None:
        self.policy = policy or ROSPolicy()

    def scan(self, root: Path, files: list[Path], text_cache: dict[Path, str]) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in files:
            if not self._looks_like_ros_file(file_path):
                continue
            text = text_cache.get(file_path)
            if not text:
                continue

            lowered = text.lower()
            if not any(hint in lowered for hint in ROS_HINTS):
                continue

            findings.extend(
                self._scan_control_surfaces(
                    root=root,
                    file_path=file_path,
                    text=text,
                    surfaces=self._dangerous_topics(),
                    finding_id="ros-dangerous-topic",
                    title="ROS topic can drive a high-risk control surface",
                    category="ros-control-plane",
                )
            )
            findings.extend(
                self._scan_control_surfaces(
                    root=root,
                    file_path=file_path,
                    text=text,
                    surfaces=self._dangerous_services(),
                    finding_id="ros-dangerous-service",
                    title="ROS service can trigger a high-risk control surface",
                    category="ros-control-plane",
                )
            )
            findings.extend(
                self._scan_control_surfaces(
                    root=root,
                    file_path=file_path,
                    text=text,
                    surfaces=self._dangerous_actions(),
                    finding_id="ros-dangerous-action",
                    title="ROS action can trigger a high-risk control surface",
                    category="ros-control-plane",
                )
            )

            if self._has_remote_wildcard_bridge(lowered):
                findings.append(
                    Finding(
                        id="rosbridge-wildcard-exposure",
                        title="rosbridge appears remotely exposed with wildcard access",
                        severity="high",
                        category="ros-control-plane",
                        location=file_path.relative_to(root).as_posix(),
                        line=self._line_number(lowered, "rosbridge"),
                        evidence="rosbridge on 0.0.0.0 with wildcard topic/service exposure",
                        remediation="Bind rosbridge locally or behind auth, and replace wildcard exposure with an explicit allowlist.",
                        scanner=self.name,
                    )
                )

            if self._mixes_sim_and_hardware(lowered):
                findings.append(
                    Finding(
                        id="ros-sim-real-mixed-control",
                        title="ROS config mixes simulation and real-hardware control hints",
                        severity="high",
                        category="sim-real-boundary",
                        location=file_path.relative_to(root).as_posix(),
                        line=self._first_mixed_line(lowered),
                        evidence="same ROS control file contains both simulation and real-hardware indicators",
                        remediation="Split simulation and real-hardware bringup into separate launch/config surfaces with explicit deployment selection.",
                        scanner=self.name,
                    )
                )
        return findings

    def _dangerous_topics(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*DEFAULT_DANGEROUS_TOPICS, *self.policy.dangerous_topics)))

    def _dangerous_services(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*DEFAULT_DANGEROUS_SERVICES, *self.policy.dangerous_services)))

    def _dangerous_actions(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*DEFAULT_DANGEROUS_ACTIONS, *self.policy.dangerous_actions)))

    def _scan_control_surfaces(
        self,
        root: Path,
        file_path: Path,
        text: str,
        surfaces: tuple[str, ...],
        finding_id: str,
        title: str,
        category: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        lowered = text.lower()
        matched_ranges: list[tuple[int, int]] = []
        for surface in surfaces:
            needle = surface.lower()
            match = re.search(rf"(?<![\w/]){re.escape(needle)}(?![\w/])", lowered)
            if not match:
                continue
            if any(start <= match.start() < end for start, end in matched_ranges):
                continue
            line_number = self._line_number(lowered, needle)
            context = self._line_context(lowered, line_number)
            if finding_id == "ros-dangerous-topic" and "service" in context:
                continue
            if finding_id == "ros-dangerous-service" and ("topic" in context or "action" in context):
                continue
            if finding_id == "ros-dangerous-action" and ("topic" in context or "service" in context):
                continue
            matched_ranges.append((match.start(), match.end()))
            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity="high",
                    category=category,
                    location=file_path.relative_to(root).as_posix(),
                    line=line_number,
                    evidence=surface,
                    remediation="Fence ROS control surfaces behind explicit capability review, approval, and deployment-mode separation.",
                    scanner=self.name,
                )
            )
        return findings

    def _has_remote_wildcard_bridge(self, lowered: str) -> bool:
        wildcard_bridge = re.search(r"(topics|services|params)_glob\s*[:=]\s*\[\s*['\"]\*['\"]\s*\]", lowered)
        return all(hint in lowered for hint in REMOTE_EXPOSURE_HINTS) and bool(wildcard_bridge)

    def _mixes_sim_and_hardware(self, lowered: str) -> bool:
        return any(hint in lowered for hint in SIM_HINTS) and any(hint in lowered for hint in HARDWARE_HINTS)

    def _first_mixed_line(self, lowered: str) -> int:
        for hint in HARDWARE_HINTS:
            if hint in lowered:
                return self._line_number(lowered, hint)
        return 1

    def _line_number(self, lowered: str, token: str) -> int:
        if token not in lowered:
            return 1
        return lowered.count("\n", 0, lowered.index(token)) + 1

    def _line_context(self, lowered: str, line_number: int, radius: int = 2) -> str:
        lines = lowered.splitlines()
        start = max(0, line_number - 1 - radius)
        end = min(len(lines), line_number)
        return "\n".join(lines[start:end])

    def _looks_like_ros_file(self, file_path: Path) -> bool:
        if file_path.suffix in ROS_FILE_SUFFIXES:
            return True
        lowered = file_path.as_posix().lower()
        return any(hint in lowered for hint in ("launch", "ros", "gazebo", "moveit", "rviz", "bringup"))
