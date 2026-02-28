/**
 * Policy engine implementation for Fortress JavaScript/TypeScript SDK
 */

import { PolicyConfig, PolicyRule, Condition, Role, Permission, Resource } from './types';

export class PolicyEngine {
  private config: PolicyConfig;
  private roles: Map<string, Role>;
  private rules: Map<string, PolicyRule>;

  constructor(config?: PolicyConfig) {
    this.config = config || {
      name: 'default',
      version: '1.0',
      rules: [],
      default_action: 'deny',
      evaluation_mode: 'all'
    };
    this.roles = new Map();
    this.rules = new Map();
  }

  async createRole(role: Role): Promise<string> {
    this.roles.set(role.id, role);
    return role.id;
  }

  async deleteRole(roleId: string): Promise<void> {
    if (!this.roles.has(roleId)) {
      throw new Error(`Role not found: ${roleId}`);
    }
    this.roles.delete(roleId);
  }

  async getRole(roleId: string): Promise<Role> {
    const role = this.roles.get(roleId);
    if (!role) {
      throw new Error(`Role not found: ${roleId}`);
    }
    return role;
  }

  async listRoles(): Promise<Role[]> {
    return Array.from(this.roles.values());
  }

  async updateRole(roleId: string, updates: Partial<Role>): Promise<void> {
    const role = this.roles.get(roleId);
    if (!role) {
      throw new Error(`Role not found: ${roleId}`);
    }
    
    const updatedRole = { ...role, ...updates };
    this.roles.set(roleId, updatedRole);
  }

  async createRule(rule: PolicyRule): Promise<string> {
    this.rules.set(rule.id, rule);
    return rule.id;
  }

  async deleteRule(ruleId: string): Promise<void> {
    if (!this.rules.has(ruleId)) {
      throw new Error(`Rule not found: ${ruleId}`);
    }
    this.rules.delete(ruleId);
  }

  async getRule(ruleId: string): Promise<PolicyRule> {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      throw new Error(`Rule not found: ${ruleId}`);
    }
    return rule;
  }

  async listRules(): Promise<PolicyRule[]> {
    return Array.from(this.rules.values());
  }

  async evaluatePolicy(
    roleId: string,
    action: string,
    resource: Resource,
    context?: any
  ): Promise<{ allowed: boolean; reason?: string; matchedRules: string[] }> {
    const role = this.roles.get(roleId);
    if (!role) {
      return {
        allowed: false,
        reason: `Role not found: ${roleId}`,
        matchedRules: []
      };
    }

    const matchedRules: string[] = [];
    let allowCount = 0;
    let denyCount = 0;

    // Check role permissions first
    for (const permission of role.permissions) {
      if (this.matchesResource(permission.resource, resource) &&
          this.matchesAction(permission.actions, action)) {
        
        if (this.evaluateConditions(permission.conditions, context)) {
          matchedRules.push(`role:${role.id}:${permission.id}`);
          
          if (permission.effect === 'allow') {
            allowCount++;
          } else {
            denyCount++;
          }
        }
      }
    }

    // Check policy rules
    for (const rule of this.rules.values()) {
      if (rule.enabled && this.evaluateRuleConditions(rule.conditions, context)) {
        matchedRules.push(`rule:${rule.id}`);
        
        if (rule.action === 'allow') {
          allowCount++;
        } else {
          denyCount++;
        }
      }
    }

    // Evaluate based on evaluation mode
    let allowed = false;
    let reason: string | undefined;

    if (this.config.evaluation_mode === 'all') {
      allowed = allowCount > 0 && denyCount === 0;
      if (!allowed) {
        reason = denyCount > 0 ? 'Denied by explicit deny rule' : 'No matching allow rules found';
      }
    } else { // 'any' mode
      allowed = allowCount > 0;
      if (!allowed) {
        reason = 'No matching allow rules found';
      }
    }

    return { allowed, reason, matchedRules };
  }

  private matchesResource(permissionResource: Resource, targetResource: Resource): boolean {
    if (permissionResource.id && targetResource.id) {
      return permissionResource.id === targetResource.id;
    }
    
    if (permissionResource.type && targetResource.type) {
      return permissionResource.type === targetResource.type;
    }
    
    return false;
  }

  private matchesAction(permissionActions: string[], targetAction: string): boolean {
    return permissionActions.includes('*') || permissionActions.includes(targetAction);
  }

  private evaluateConditions(conditions: Condition[] | undefined, context: any): boolean {
    if (!conditions || conditions.length === 0) {
      return true;
    }

    return conditions.every(condition => this.evaluateCondition(condition, context));
  }

  private evaluateRuleConditions(conditions: Condition[] | undefined, context: any): boolean {
    if (!conditions || conditions.length === 0) {
      return true;
    }

    return conditions.every(condition => this.evaluateCondition(condition, context));
  }

  private evaluateCondition(condition: Condition, context: any): boolean {
    if (!context) {
      return true;
    }

    const fieldValue = this.getFieldValue(context, condition.field);
    const conditionValue = condition.value;

    switch (condition.operator) {
      case 'eq':
        return fieldValue === conditionValue;
      case 'ne':
        return fieldValue !== conditionValue;
      case 'gt':
        return Number(fieldValue) > Number(conditionValue);
      case 'gte':
        return Number(fieldValue) >= Number(conditionValue);
      case 'lt':
        return Number(fieldValue) < Number(conditionValue);
      case 'lte':
        return Number(fieldValue) <= Number(conditionValue);
      case 'in':
        return Array.isArray(conditionValue) && conditionValue.includes(fieldValue);
      case 'contains':
        return String(fieldValue).includes(String(conditionValue));
      default:
        return false;
    }
  }

  private getFieldValue(obj: any, field: string): any {
    return field.split('.').reduce((current, key) => current?.[key], obj);
  }

  async assignRoleToUser(userId: string, roleId: string): Promise<void> {
    // In a real implementation, this would store the user-role mapping
    // For now, we'll just validate the role exists
    const role = this.roles.get(roleId);
    if (!role) {
      throw new Error(`Role not found: ${roleId}`);
    }
  }

  async removeRoleFromUser(userId: string, roleId: string): Promise<void> {
    // In a real implementation, this would remove the user-role mapping
  }

  async getUserRoles(userId: string): Promise<string[]> {
    // In a real implementation, this would fetch user roles from storage
    return [];
  }

  async checkPermission(
    userId: string,
    resource: Resource,
    action: string,
    context?: any
  ): Promise<{ allowed: boolean; reason?: string }> {
    const userRoles = await this.getUserRoles(userId);
    
    for (const roleId of userRoles) {
      const result = await this.evaluatePolicy(roleId, action, resource, context);
      if (result.allowed) {
        return { allowed: true };
      }
    }

    return { allowed: false, reason: 'No permissions granted' };
  }
}
