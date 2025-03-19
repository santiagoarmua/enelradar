package service;

import entity.Show;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import repository.ShowRepository;

import java.util.List;
import java.util.Optional;

@Service
public class ShowService {
    private final ShowRepository showRepository;

    @Autowired
    public ShowService(ShowRepository showRepository) {
        this.showRepository = showRepository;
    }

    public Optional<Show> getShowById(Integer id) {
        return showRepository.findById(id);
    }

    public List<Show> getAllShows() {
        return showRepository.findAll();
    }

    public Show saveShow(Show show) {
        return showRepository.save(show);
    }

    public void deleteShow(Integer id) {
        showRepository.deleteById(id);
    }
}

