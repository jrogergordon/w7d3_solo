class User < ApplicationRecord

    validates :email, presence: true, uniqueness: true
    validates :password_digest, presence: true
    validates :session_token, presence: true, uniqueness: true
    validates :password, length: {minimum: 6, allow_nil: true}
    attr_reader :password

    after_initialize :ensure_session_token

    def self.generate_session_token
        self.session_token = SecureRandom.urlsafe_base64
    end

    def reset_session_token!
        self.session_token = SecureRandom.urlsafe_base64
        self.save!
        self.session_token
    end

    def ensure_session_token
        self.session_token ||= SecureRandom.urlsafe_base64
    end

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        self.password_digest == BCrypt::Password.create(password)
    end

    def self.find_by_credentials(username, password)
        user = User.find_by(username: username)

        if user != nil
            user.is_password?(password) ? user : nil
        end
        nil
    end
end
