#!/usr/bin/env python3
# Group VMs by project, format display names

class VMGrouper:
    @staticmethod
    def get_display_name(vm_name, metadata):
        display = metadata.get('display_name', 'Unknown')
        project = metadata.get('project', 'Unknown')
        if display and display != 'Unknown':
            return f"[{project}] {display}"
        if project and project != 'Unknown':
            return f"[{project}] {vm_name}"
        return vm_name

    @staticmethod
    def get_vm_identifier(vm_name, metadata):
        display = VMGrouper.get_display_name(vm_name, metadata)
        return f"{display} ({vm_name})"

    @staticmethod
    def group_vms_by_project(vms_data):
        grouped = {}
        for vm in vms_data:
            project = vm.get('project', 'Unknown')
            if project not in grouped:
                grouped[project] = []
            grouped[project].append(vm)
        return grouped

    @staticmethod
    def group_alerts_by_project(alerts):
        return VMGrouper.group_vms_by_project(alerts)

    @staticmethod
    def format_vm_summary(vm_name, metadata, cpu_percent, parameter_a, status):
        identifier = VMGrouper.get_vm_identifier(vm_name, metadata)
        emoji = "🔴" if status == "Crítico" else "🟡" if status == "Alto" else "🟢"
        return f"{emoji} {identifier} - CPU: {cpu_percent:.1f}% | A: {parameter_a:.1f}"


class ProjectMetrics:
    def __init__(self):
        self.metrics = {}

    def add_vm_metric(self, project, vm_name, cpu_percent, parameter_a, status):
        if project not in self.metrics:
            self.metrics[project] = {
                'vms': [], 'total_cpu': 0, 'total_a': 0,
                'critical': 0, 'alto': 0, 'normal': 0
            }
        m = self.metrics[project]
        m['vms'].append(vm_name)
        m['total_cpu'] += cpu_percent
        m['total_a'] += parameter_a
        if status == "Crítico":
            m['critical'] += 1
        elif status == "Alto":
            m['alto'] += 1
        else:
            m['normal'] += 1

    def get_project_summary(self, project):
        if project not in self.metrics:
            return {}
        m = self.metrics[project]
        total = len(m['vms'])
        if total == 0:
            return {}
        return {
            'project': project,
            'total_vms': total,
            'avg_cpu': m['total_cpu'] / total,
            'avg_a': m['total_a'] / total,
            'critical': m['critical'],
            'alto': m['alto'],
            'normal': m['normal']
        }
