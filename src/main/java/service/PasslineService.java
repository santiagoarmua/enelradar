package service;

import entity.Passline;
import entity.Payment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import repository.PasslineRepository;

import java.util.List;
import java.util.Optional;

@Service
public class PasslineService {
    private final PasslineRepository passlineRepository;

    @Autowired
    public PasslineService(PasslineRepository passlineRepository) {
        this.passlineRepository = passlineRepository;
    }

    public Optional<Passline> getPasslineById(Integer id) {
        return passlineRepository.findById(id);
    }

    public List<Passline> findAll() {
        return passlineRepository.findAll();
    }

    public Passline savePassline(Passline passline) {
        return passlineRepository.save(passline);
    }

    public void deletePassline(Integer id) {
        passlineRepository.deleteById(id);
    }
}

