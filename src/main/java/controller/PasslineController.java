package controller;

import entity.Passline;
import entity.Payment;
import entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import service.PasslineService;

import java.util.List;

@RestController
@RequestMapping("/passlines")
public class PasslineController {
    private final PasslineService passlineService;

    @Autowired
    public PasslineController(PasslineService passlineService) {
        this.passlineService = passlineService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Passline> getPassline(@PathVariable Integer id) {
        return passlineService.getPasslineById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping
    public ResponseEntity<List<Passline>> getAllPasslines() {
        List<Passline> passlines = passlineService.findAll();
        return ResponseEntity.ok(passlines);
    }

    @PostMapping
    public ResponseEntity<Passline> createPassline(@RequestBody Passline passline) {
        Passline savedPassline = passlineService.savePassline(passline);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedPassline);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Passline> updatePassline(@PathVariable Integer id, @RequestBody Passline passline) {
        return passlineService.getPasslineById(id)
                .map(existingPassline -> {
                    passline.setIdPassline(id);
                    Passline updatedPassline = passlineService.savePassline(passline);
                    return ResponseEntity.ok(updatedPassline);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePassline(@PathVariable Integer id) {
        if (passlineService.getPasslineById(id).isPresent()) {
            passlineService.deletePassline(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
}
