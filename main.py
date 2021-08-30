import re

LEN = 'LEN'
SPECIALS = 'SPECIALS'
NUMBERS = 'NUMBERS'
LETTERS = 'LETTERS'

# Types of comparator
equal = '='
lt = '<'
gt = '>'

verifications = [LEN, SPECIALS, NUMBERS, LETTERS]
comparators = [equal, lt, gt]

class PasswordValidator:
    """
    PasswordValidator is a class that validates a password based on a set of rules.
    """
    def __init__(self, rules):
        self.rules = rules
    
    def is_valid(self, password):
        """
        Return True if the password is valid, False otherwise.
        """
        return all(rule.validate(password) is None for rule in self.rules)
    
    def errors(self, password):
        """
        Return a list of errors found in the password.
        """
        checked_errors = [rule.validate(password) for rule in self.rules]
        return [error for error in checked_errors if error]
    


class PasswordRules:
    """
    A class that contains rules for validating a password.
    examples of rules: 
        LEN > 8
        SPECIALS = 1 
        NUMBERS > 3
        LETTERS = 4
    """

    def __init__(self, rule_type, comparator, value):
        if rule_type not in verifications:
            raise ValueError('Invalid rule type')
        
        if comparator not in comparators:
            raise ValueError('Invalid comparator type')
    
        self.rule_type = rule_type
        self.comparator = comparator
        self.value = value

        if self.comparator == equal:
            self.comparator_name = 'equals'
        elif self.comparator == lt:
            self.comparator_name = 'less than'
        elif self.comparator == gt:
            self.comparator_name = 'greater than'

    def _count_symbols(self, password):
        """
        Counts the number of symbols (for a given rule_type) in the password
        """ 
        if self.rule_type == LETTERS:
            return len(re.findall(r'[a-zA-Z]', password))
        elif self.rule_type == NUMBERS:
            return len(re.findall(r'[0-9]', password))
        elif self.rule_type == SPECIALS:
            return len(re.findall(r'[!@#$%^&*()_+=-]', password))
        return len(password)

    def validate(self, password):
        """
        Verify if the password satisfies the rule defined by the rule_type, comparator and value parameters.
        A None return indicate that the password does satisfy the rule and no errors were found.
        """
        count = self._count_symbols(password)
        
        if self.comparator == equal:
            return None if count == self.value else self._error_msg(count)
        elif self.comparator == lt:
            return None if count < self.value else self._error_msg(count)
        elif self.comparator == gt:
            return None if count > self.value else self._error_msg(count)
        return None
    
    def _error_msg(self, count):
        return 'the amount of {} symbols should be {} to {}'.format(self.rule_type.lower(), 
            self.comparator_name, self.value)
    
def create_password_validator(requirements):
    """
    Create a PasswordValidator object from a list of requirements in the format:
        requirements = [('LEN' , '=', 8), ('SPECIALS' , '<', 1), ('NUMBERS' , '>', 3), ('LETTERS' , '=', 4)]
    """
    rules = []
    for rule_type, comparator, value in requirements:
        rules.append(PasswordRules(rule_type, comparator, value))
    return PasswordValidator(rules)
    

if __name__ == '__main__':
    def password_tester(test_case_description,password, requirement):
        """
        Test a password against a requirement.
        """
        print('Test case: {}'.format(test_case_description))
        validator = create_password_validator(requirement)
        errors = validator.errors(password)
        if errors:
            print('Errors found: {}'.format(errors))
            print('Password {} is not valid'.format(password))
        else:
            print('>Password is valid')
        print()
    
    test_cases = [
        ('A password should contain exactly 9 letters', "abdfghrty", [('LEN', '=', 9)]),
        ('A password should contain at least 8 letters', "abdfghrty", [('LEN', '>', 8)]),
        ('A password should contain at most 8 letters', "wertghy", [('LEN', '<', 8)]),
        ('A password should contain at least 1 special character', "meuP@ssword", [('SPECIALS', '>', 0)]),
        ('A password should not contain any special character', "adff", [('SPECIALS', '=', 0)]),
        ('A password should contain at least 3 numbers', "12345678", [('NUMBERS', '>', 3)]),
        ('A password should contain at most 3 numbers', "abc123", [('NUMBERS', '<', 4)]),
        ('A password should contain at least 4 letters', "abcdefgh", [('LETTERS', '>', 4)]),
        ('A password should contain at most 4 letters', "aref#", [('LETTERS', '<', 5)]),
        ('A password should contain at most 2 letters, 3 numbers and 1 special character', "ab123#", [('LETTERS', '<', 3), ('NUMBERS', '<', 4), ('SPECIALS', '<', 2)]),
        ('A password should contain at least 3 letters, 3 numbers and 1 special character', "abcd1234#", [('LETTERS', '>', 3), ('NUMBERS', '>', 3), ('SPECIALS', '>', 0)]),
        ('A password should contain at most 3 letters, 3 numbers and 1 special character', "ab23!", [('LETTERS', '<', 3), ('NUMBERS', '<', 3), ('SPECIALS', '<', 2)]),
        ('A password should contain at least 1 special character and 2 letters', "a@bcdefgh", [('SPECIALS', '>', 0), ('LETTERS', '>', 1)]),
        ('A password should contain length 10 and at least 2 special characters', "abcdef#ghijklmnopqrstuvwxy@z", [('LEN', '>', 10), ('SPECIALS', '>', 1)]),
    ]

    
    for test_case in test_cases:
        password_tester(*test_case)
    



