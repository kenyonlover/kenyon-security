package top.kenyon.kenyonsecurity.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import top.kenyon.kenyonsecurity.entity.User;

public interface UserDao extends JpaRepository<User,Long> {
    User findUserByUsername(String username);
}
