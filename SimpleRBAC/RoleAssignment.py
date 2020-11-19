class RoleAssignment(object):
    """Defines the detailed access control rules
    
    If a role is not given an explicit resource authorisation, it's rejected by default. Rule of Least privileges.
    """

    def __init__(self):
        self._read = []
        self._write = []
        self._delete = []

    def resource_read_rule(self, role, method, resource):
        """Add rules to allow read access
        
        :param role: Role of this rule
        :param method: REST verbs allowed to access resource. Include GET, PUT et al.
        :param resource: The resource in question
        """
        permission = (role.get_name(), method, resource)
        if permission not in self._read:
            self._read.append(permission)

    def resource_write_rule(self, role, method, resource):
        """Add rules to allow write access
        
        :param role: Role of this rule
        :param method: REST verbs allowed to access resource. Include GET, PUT et al.
        :param resource: The resource in question
        """
        permission = (role.get_name(), method, resource)
        if permission not in self._write:
            self._write.append(permission)

    def resource_delete_rule(self, role, method, resource):
        """Add rules to allow full access.
        
        :param role: Role of this rule
        :param method: REST verbs allowed to access resource. Include GET, PUT et al.
        :param resource: The resource in question
        """
        permission = (role.get_name(), method, resource)
        if permission not in self._delete:
            self._delete.append(permission)

    def is_read_allowed(self, role, method, resource):
        """returns whether the role is allowed READ access resource
        :return: Boolean
        """
        return (role, method, resource) in self._read

    def is_write_allowed(self, role, method, resource):
        """returns whether the role is allowed WRITE access resource
        :return: Boolean
        """
        return (role, method, resource) in self._write

    def is_delete_allowed(self, role, method, resource):
        """returns whether the role is allowed DELETE access resource
        :return: Boolean
        """
        return (role, method, resource) in self._delete