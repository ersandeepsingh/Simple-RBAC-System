from SimpleRBAC import RoleAssignment, User, Role

everyone_role = Role('everyone')
admin_role = Role('admin')

everyone_user = User(roles=[everyone_role])
admin_user = User(roles=[admin_role, everyone_role])


assignrole = RoleAssignment()

assignrole.resource_read_rule(everyone_role, 'GET', '/api/v1/employee/1/info')
assignrole.resource_delete_rule(admin_role, 'DELETE', '/api/v1/employee/1/')


class TestPermissions():

    def test_read_rule_everyone(self):
        """checking resource access with the employee himself in context
        """
        for user_role in [role.get_name() for role in everyone_user.get_roles()]:
            assert assignrole.is_read_allowed(user_role, 'GET', '/api/v1/employee/1/info') == True

    def test_write_rule_everyone(self):
        """write operation by the role 'everyone' should fail
        """
        for user_role in [role.get_name() for role in everyone_user.get_roles()]:
            assert assignrole.is_write_allowed(user_role, 'WRITE', '/api/v1/employee/1/info') == False

    def test_delete_rule_admin(self):
        """admin role should be able to read
        """
        for user_role in [role.get_name() for role in everyone_user.get_roles()]:
            if user_role == 'admin':
                assert assignrole.is_delete_allowed(user_role, 'DELETE', '/api/v1/employee/1/') == True
            else:
                assert assignrole.is_delete_allowed(user_role, 'DELETE', '/api/v1/employee/1/') == False

