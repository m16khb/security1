package com.cos.security1.repository;

import com.cos.security1.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

//CRUD함수를 JpaRepository가 들고 잇음
//@Repository라는 어노테이션이 없어도 IOC가 된다...? 이유는 JpaRepository가 가지고 있기 때문에...?
public interface UserRepository extends JpaRepository<User, Integer> {
}
