export enum UserRole {
  TENANT_ADMIN = 'tenant_admin',
  MANAGER = 'manager',
  AGENT = 'agent',
  AUDITOR = 'auditor',
}

export enum Permission {
  // User management
  USERS_CREATE = 'users:create',
  USERS_READ = 'users:read',
  USERS_UPDATE = 'users:update',
  USERS_DELETE = 'users:delete',
  USERS_MANAGE_ROLES = 'users:manage_roles',

  // Tenant management
  TENANT_READ = 'tenant:read',
  TENANT_UPDATE = 'tenant:update',
  TENANT_DELETE = 'tenant:delete',
  TENANT_MANAGE_SETTINGS = 'tenant:manage_settings',

  // Session management
  SESSIONS_CREATE = 'sessions:create',
  SESSIONS_READ = 'sessions:read',
  SESSIONS_UPDATE = 'sessions:update',
  SESSIONS_DELETE = 'sessions:delete',
  SESSIONS_MANAGE = 'sessions:manage',

  // Message management
  MESSAGES_SEND = 'messages:send',
  MESSAGES_READ = 'messages:read',
  MESSAGES_READ_ASSIGNED = 'messages:read:assigned',
  MESSAGES_DELETE = 'messages:delete',
  MESSAGES_MANAGE = 'messages:manage',

  // Reports and analytics
  REPORTS_READ = 'reports:read',
  ANALYTICS_READ = 'analytics:read',

  // Webhook management
  WEBHOOKS_CREATE = 'webhooks:create',
  WEBHOOKS_READ = 'webhooks:read',
  WEBHOOKS_UPDATE = 'webhooks:update',
  WEBHOOKS_DELETE = 'webhooks:delete',

  // System administration
  SYSTEM_LOGS_READ = 'system:logs:read',
  SYSTEM_SETTINGS_READ = 'system:settings:read',
  SYSTEM_SETTINGS_UPDATE = 'system:settings:update',
}

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  [UserRole.TENANT_ADMIN]: [
    // Full access to everything
    Permission.USERS_CREATE,
    Permission.USERS_READ,
    Permission.USERS_UPDATE,
    Permission.USERS_DELETE,
    Permission.USERS_MANAGE_ROLES,
    Permission.TENANT_READ,
    Permission.TENANT_UPDATE,
    Permission.TENANT_DELETE,
    Permission.TENANT_MANAGE_SETTINGS,
    Permission.SESSIONS_CREATE,
    Permission.SESSIONS_READ,
    Permission.SESSIONS_UPDATE,
    Permission.SESSIONS_DELETE,
    Permission.SESSIONS_MANAGE,
    Permission.MESSAGES_SEND,
    Permission.MESSAGES_READ,
    Permission.MESSAGES_READ_ASSIGNED,
    Permission.MESSAGES_DELETE,
    Permission.MESSAGES_MANAGE,
    Permission.REPORTS_READ,
    Permission.ANALYTICS_READ,
    Permission.WEBHOOKS_CREATE,
    Permission.WEBHOOKS_READ,
    Permission.WEBHOOKS_UPDATE,
    Permission.WEBHOOKS_DELETE,
    Permission.SYSTEM_LOGS_READ,
    Permission.SYSTEM_SETTINGS_READ,
    Permission.SYSTEM_SETTINGS_UPDATE,
  ],

  [UserRole.MANAGER]: [
    // Campaign and messaging management
    Permission.USERS_READ,
    Permission.TENANT_READ,
    Permission.SESSIONS_CREATE,
    Permission.SESSIONS_READ,
    Permission.SESSIONS_UPDATE,
    Permission.SESSIONS_DELETE,
    Permission.SESSIONS_MANAGE,
    Permission.MESSAGES_SEND,
    Permission.MESSAGES_READ,
    Permission.MESSAGES_READ_ASSIGNED,
    Permission.MESSAGES_MANAGE,
    Permission.REPORTS_READ,
    Permission.ANALYTICS_READ,
    Permission.WEBHOOKS_CREATE,
    Permission.WEBHOOKS_READ,
    Permission.WEBHOOKS_UPDATE,
    Permission.WEBHOOKS_DELETE,
  ],

  [UserRole.AGENT]: [
    // Basic messaging operations
    Permission.SESSIONS_READ,
    Permission.MESSAGES_SEND,
    Permission.MESSAGES_READ_ASSIGNED,
    Permission.WEBHOOKS_READ,
  ],

  [UserRole.AUDITOR]: [
    // Read-only access
    Permission.USERS_READ,
    Permission.TENANT_READ,
    Permission.SESSIONS_READ,
    Permission.MESSAGES_READ,
    Permission.REPORTS_READ,
    Permission.ANALYTICS_READ,
    Permission.WEBHOOKS_READ,
    Permission.SYSTEM_LOGS_READ,
  ],
};

export const HIERARCHICAL_ROLES: Record<UserRole, UserRole[]> = {
  [UserRole.TENANT_ADMIN]: [UserRole.MANAGER, UserRole.AGENT, UserRole.AUDITOR],
  [UserRole.MANAGER]: [UserRole.AGENT, UserRole.AUDITOR],
  [UserRole.AGENT]: [],
  [UserRole.AUDITOR]: [],
};
