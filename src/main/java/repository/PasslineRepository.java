package repository;

import entity.Passline;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PasslineRepository extends JpaRepository<Passline, Integer> {

}