package controller;

import entity.Show;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import service.ShowService;

import java.util.List;

@RestController
@RequestMapping("/shows")
public class ShowController {
    private final ShowService showService;

    @Autowired
    public ShowController(ShowService showService) {
        this.showService = showService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Show> getShow(@PathVariable Integer id) {
        return showService.getShowById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<Show> getAllShows() {
        return showService.getAllShows();
    }

    @PostMapping
    public ResponseEntity<Show> createShow(@RequestBody Show show) {
        Show savedShow = showService.saveShow(show);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedShow);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Show> updateShow(@PathVariable Integer id, @RequestBody Show show) {
        return showService.getShowById(id)
                .map(existingShow -> {
                    show.setId(id);
                    Show updatedShow = showService.saveShow(show);
                    return ResponseEntity.ok(updatedShow);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteShow(@PathVariable Integer id) {
        if (showService.getShowById(id).isPresent()) {
            showService.deleteShow(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
}
